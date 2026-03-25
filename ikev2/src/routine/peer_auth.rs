use anyhow::{Context, Result, bail, ensure};
use bytemuck::{Pod, Zeroable, bytes_of};
use bytes::Bytes;
use hex_literal::hex;
use rustls_pki_types::CertificateDer;

use super::{Ikev2Routine, PeerIdentity, common::ParsedSignatureAuth, ids::rightid_matches};
use crate::{
    cipher::{self, SHA1_HASHER},
    consts::{
        NOTIFY_TYPE_ADDITIONAL_TS_POSSIBLE, NOTIFY_TYPE_AUTHENTICATION_FAILED,
        NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION, NOTIFY_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED,
        NOTIFY_TYPE_FAILED_CP_REQUIRED, NOTIFY_TYPE_FRAGMENTATION_SUPPORTED,
        NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC, NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED,
        NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE, NOTIFY_TYPE_IPCOMP_SUPPORTED,
        NOTIFY_TYPE_NO_ADDITIONAL_SAS, NOTIFY_TYPE_NO_PROPOSAL_CHOSEN,
        NOTIFY_TYPE_NON_FIRST_FRAGMENTS_ALSO, NOTIFY_TYPE_SINGLE_PAIR_REQUIRED,
        NOTIFY_TYPE_TS_UNACCEPTABLE, NOTIFY_TYPE_USE_TRANSPORT_MODE,
    },
};

const_variant!(
    u8:
    AUTH_METHOD_RSA_DIGITAL_SIGNATURE = 1u8;
    AUTH_METHOD_SHARED_KEY_MIC = 2u8;
    AUTH_METHOD_DSS_DIGITAL_SIGNATURE = 3u8;
    AUTH_METHOD_DIGITAL_SIGNATURE = 14u8;
);

const_variant!(
    u16:
    HASH_ALGORITHM_SHA2_256 = 2u16;
    HASH_ALGORITHM_SHA2_384 = 3u16;
    HASH_ALGORITHM_SHA2_512 = 4u16;
);

const_variant!(
    &'static [u8]:
    ASN1_RSA_SHA256 = &hex!("300d06092a864886f70d01010b0500");
    ASN1_RSA_SHA384 = &hex!("300d06092a864886f70d01010c0500");
    ASN1_RSA_SHA512 = &hex!("300d06092a864886f70d01010d0500");
    ASN1_ECDSA_SHA256 = &hex!("300a06082a8648ce3d040302");
    ASN1_ECDSA_SHA384 = &hex!("300a06082a8648ce3d040303");
    ASN1_ECDSA_SHA512 = &hex!("300a06082a8648ce3d040304");
);

const IKEV2_KEY_PAD: &[u8] = b"Key Pad for IKEv2";
const SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY: &str = "SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY";

impl Ikev2Routine {
    pub(super) fn build_local_auth_payload(
        &self,
        idi_type: u8,
        idi_identity: &[u8],
    ) -> Result<Bytes> {
        #[repr(C)]
        #[derive(Clone, Copy, Zeroable, Pod)]
        struct AuthPayloadHeader {
            // AUTH method plus the 24-bit reserved field.
            auth_method: u8,
            reserved: [u8; 3],
        }

        let idi_payload = self
            .sa
            .auth
            .first_idi_payload
            .clone()
            .unwrap_or_else(|| Self::build_id_payload_typed(idi_type, idi_identity));
        crate::debug_fmt::log_auth_bytes("local IDx' =>", idi_payload.as_ref());
        let mac = self.compute_local_auth_mac(idi_payload.as_ref())?;
        crate::debug_fmt::log_auth_bytes("local AUTH =>", mac.as_ref());
        let mut payload = Vec::with_capacity(4 + mac.len());
        payload.extend_from_slice(bytes_of(&AuthPayloadHeader {
            auth_method: AUTH_METHOD_SHARED_KEY_MIC,
            reserved: [0; 3],
        }));
        payload.extend_from_slice(&mac);
        Ok(Bytes::from(payload))
    }

    pub(super) fn verify_peer_auth_payload(
        &self,
        idr_payload: &[u8],
        auth_payload: &[u8],
    ) -> Result<u8> {
        ensure!(auth_payload.len() >= 4, "invalid AUTH payload");
        ensure!(auth_payload[1..4] == [0, 0, 0], "invalid AUTH payload");
        let auth_method = auth_payload[0];
        let auth_data = &auth_payload[4..];
        match auth_method {
            AUTH_METHOD_SHARED_KEY_MIC => {
                let expected = self.compute_peer_auth_mac(idr_payload)?;
                crate::debug_fmt::log_auth_bytes("peer IDx' =>", idr_payload);
                crate::debug_fmt::log_auth_bytes("peer AUTH recv =>", auth_data);
                crate::debug_fmt::log_auth_bytes("peer AUTH expect =>", expected.as_ref());
                ensure!(auth_data == expected.as_ref(), "AUTH verification failed");
            }
            AUTH_METHOD_DIGITAL_SIGNATURE => {
                let octets = self.compute_peer_signed_octets(idr_payload)?;
                self.verify_peer_signature_auth_method_14(idr_payload, auth_data, octets.as_ref())?;
            }
            AUTH_METHOD_RSA_DIGITAL_SIGNATURE | AUTH_METHOD_DSS_DIGITAL_SIGNATURE => {
                let octets = self.compute_peer_signed_octets(idr_payload)?;
                self.verify_peer_signature_auth(
                    idr_payload,
                    auth_method,
                    auth_data,
                    octets.as_ref(),
                )?;
            }
            _ => bail!("unsupported AUTH method {auth_method}"),
        }
        Ok(auth_method)
    }

    fn compute_peer_auth_mac(&self, idr_payload: &[u8]) -> Result<Bytes> {
        let octets = self.compute_peer_signed_octets(idr_payload)?;
        crate::debug_fmt::log_auth_bytes("peer AUTH octets =>", octets.as_ref());
        let keys = self.sa.key_material.as_ref().context("IKE key material is missing")?;
        let selection = self.selected_ike_proposal()?;
        let auth_secret = self.sa.auth.local_eap_msk.as_deref().unwrap_or(keys.sk_pr.as_ref());
        crate::debug_fmt::log_auth_bytes("peer AUTH secret =>", auth_secret);
        let key = selection
            .prf
            .gen_prf_vec(auth_secret, IKEV2_KEY_PAD)
            .context("compute responder AUTH key")?;
        crate::debug_fmt::log_auth_bytes("peer AUTH keypad prf =>", key.as_ref());
        let mac = selection
            .prf
            .gen_prf_vec(&key, octets.as_ref())
            .context("compute responder AUTH MAC")?;
        Ok(Bytes::from(mac))
    }

    fn compute_local_auth_mac(&self, idi_payload: &[u8]) -> Result<Bytes> {
        let octets = self.compute_local_signed_octets(idi_payload)?;
        crate::debug_fmt::log_auth_bytes("local AUTH octets =>", octets.as_ref());
        let keys = self.sa.key_material.as_ref().context("IKE key material is missing")?;
        let selection = self.selected_ike_proposal()?;
        let auth_secret = self.sa.auth.local_eap_msk.as_deref().unwrap_or(keys.sk_pi.as_ref());
        crate::debug_fmt::log_auth_bytes("local AUTH secret =>", auth_secret);
        let key = selection
            .prf
            .gen_prf_vec(auth_secret, IKEV2_KEY_PAD)
            .context("compute initiator AUTH key")?;
        crate::debug_fmt::log_auth_bytes("local AUTH keypad prf =>", key.as_ref());
        let mac = selection
            .prf
            .gen_prf_vec(&key, octets.as_ref())
            .context("compute initiator AUTH MAC")?;
        Ok(Bytes::from(mac))
    }

    fn compute_peer_signed_octets(&self, idr_payload: &[u8]) -> Result<Vec<u8>> {
        let keys = self.sa.key_material.as_ref().context("IKE key material is missing")?;
        let init_response = self
            .sa
            .sa_init_response
            .as_ref()
            .context("IKE_SA_INIT responder packet missing")?
            .clone();
        let ni = self.sa.initiator_nonce.as_ref().context("initiator nonce missing")?;
        let selection = self.selected_ike_proposal()?;
        let maced_id = selection
            .prf
            .gen_prf_vec(keys.sk_pr.as_ref(), idr_payload)
            .context("compute responder MACedID")?;
        crate::debug_fmt::log_auth_bytes("peer AUTH sa_init_resp =>", init_response.as_ref());
        crate::debug_fmt::log_auth_bytes("peer AUTH nonce =>", ni);
        crate::debug_fmt::log_auth_bytes("peer AUTH maced ID =>", maced_id.as_ref());
        let mut octets = Vec::with_capacity(init_response.len() + ni.len() + maced_id.len());
        octets.extend_from_slice(init_response.as_ref());
        octets.extend_from_slice(ni);
        octets.extend_from_slice(&maced_id);
        Ok(octets)
    }

    fn compute_local_signed_octets(&self, idi_payload: &[u8]) -> Result<Vec<u8>> {
        let keys = self.sa.key_material.as_ref().context("IKE key material is missing")?;
        let init_request = self
            .sa
            .sa_init_request
            .as_ref()
            .context("IKE_SA_INIT initiator packet missing")?
            .clone();
        let nr = self.sa.responder_nonce.as_ref().context("responder nonce missing")?;
        let selection = self.selected_ike_proposal()?;
        let maced_id = selection
            .prf
            .gen_prf_vec(keys.sk_pi.as_ref(), idi_payload)
            .context("compute initiator MACedID")?;
        let mut octets = Vec::with_capacity(init_request.len() + nr.len() + maced_id.len());
        octets.extend_from_slice(init_request.as_ref());
        octets.extend_from_slice(nr);
        octets.extend_from_slice(&maced_id);
        Ok(octets)
    }

    fn verify_peer_signature_auth(
        &self,
        idr_payload: &[u8],
        auth_method: u8,
        signature: &[u8],
        octets: &[u8],
    ) -> Result<()> {
        match auth_method {
            AUTH_METHOD_RSA_DIGITAL_SIGNATURE | AUTH_METHOD_DSS_DIGITAL_SIGNATURE => {}
            _ => bail!("unsupported signature AUTH method {auth_method}"),
        };
        cipher::verify_peer_auth_signature(
            &self.peer_cert_chain_der(),
            idr_payload,
            octets,
            signature,
            &SHA1_HASHER,
            None,
            insecure_skip_peer_cert_chain_verify(),
        )
    }

    fn verify_peer_signature_auth_method_14(
        &self,
        idr_payload: &[u8],
        auth_data: &[u8],
        octets: &[u8],
    ) -> Result<()> {
        ensure!(
            !self.sa.auth.peer_signature_hash_algorithms.is_empty(),
            "responder used AUTH method 14 without SIGNATURE_HASH_ALGORITHMS negotiation"
        );
        let parsed = Self::parse_signature_auth_data(auth_data)?;
        ensure!(
            self.sa.auth.peer_signature_hash_algorithms.contains(&parsed.hash_algorithm),
            "AUTH method 14 used unadvertised signature hash algorithm {}",
            parsed.hash_algorithm
        );

        cipher::verify_peer_auth_signature(
            &self.peer_cert_chain_der(),
            idr_payload,
            octets,
            parsed.signature,
            parsed.hash.as_ref(),
            Some(parsed.public_key_type),
            insecure_skip_peer_cert_chain_verify(),
        )
    }

    fn peer_cert_chain_der(&self) -> Vec<CertificateDer<'static>> {
        cipher::build_peer_cert_chain(
            self.sa.auth.peer_cert_der.as_ref(),
            &self.sa.auth.peer_cert_chain,
        )
    }

    pub(super) fn decode_cert_payload(payload: &[u8]) -> Result<(u8, &[u8])> {
        ensure!(!payload.is_empty(), "invalid CERT payload");
        Ok((payload[0], &payload[1..]))
    }

    pub(super) fn validate_ike_auth_notifies(&mut self, notifies: &[u16]) -> Result<()> {
        for notify_type in notifies {
            if matches!(
                *notify_type,
                NOTIFY_TYPE_ADDITIONAL_TS_POSSIBLE
                    | NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION
                    | NOTIFY_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED
                    | NOTIFY_TYPE_FRAGMENTATION_SUPPORTED
                    | NOTIFY_TYPE_IPCOMP_SUPPORTED
                    | NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED
                    | NOTIFY_TYPE_NON_FIRST_FRAGMENTS_ALSO
                    | NOTIFY_TYPE_USE_TRANSPORT_MODE
            ) || Self::is_ike_auth_child_failure_notify(*notify_type)
            {
                continue;
            }
            if *notify_type == NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC {
                bail!("received unsupported IKEV2_MESSAGE_ID_SYNC notify");
            }
            if *notify_type == NOTIFY_TYPE_AUTHENTICATION_FAILED {
                self.broken = true;
                self.sa.suppress_error_auth_failed_notify = true;
                bail!("received AUTHENTICATION_FAILED notify");
            }
            if *notify_type < 16384 {
                bail!("received IKE_AUTH notify error type {notify_type}");
            }
        }
        Ok(())
    }

    pub(super) fn is_ike_auth_child_failure_notify(notify_type: u16) -> bool {
        matches!(
            notify_type,
            NOTIFY_TYPE_FAILED_CP_REQUIRED
                | NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE
                | NOTIFY_TYPE_NO_ADDITIONAL_SAS
                | NOTIFY_TYPE_NO_PROPOSAL_CHOSEN
                | NOTIFY_TYPE_SINGLE_PAIR_REQUIRED
                | NOTIFY_TYPE_TS_UNACCEPTABLE
        )
    }

    pub(super) fn record_peer_identity(&mut self, payload: Bytes) -> Result<()> {
        ensure!(payload.len() >= super::common::ID_PAYLOAD_FIXED_FIELDS_LEN, "invalid ID payload");
        let id_type = payload[0];
        let value = payload.slice(super::common::ID_PAYLOAD_FIXED_FIELDS_LEN..);
        if let Some(expected) = self.expected_rightid() {
            ensure!(
                rightid_matches(expected, id_type, value.as_ref()),
                "rightid mismatch: expected value {expected}, received type {id_type} value {}",
                String::from_utf8_lossy(&value)
            );
        }
        self.peer_identity =
            Some(PeerIdentity { id_type, value: value.to_vec().into_boxed_slice() });
        Ok(())
    }

    fn parse_signature_auth_data(auth_data: &[u8]) -> Result<ParsedSignatureAuth<'_>> {
        ensure!(auth_data.len() >= 2, "invalid AUTH method 14 payload");
        let asn1_len = auth_data[0] as usize;
        ensure!(asn1_len != 0, "AUTH method 14 missing AlgorithmIdentifier");
        ensure!(auth_data.len() > 1 + asn1_len, "AUTH method 14 missing signature value");
        let algorithm_identifier = &auth_data[1..1 + asn1_len];
        let signature = &auth_data[1 + asn1_len..];

        let (hash_algorithm, hash, public_key_type) = match algorithm_identifier {
            ASN1_RSA_SHA256 => (HASH_ALGORITHM_SHA2_256, cipher::sha256(), cipher::PKEY_KIND_RSA),
            ASN1_RSA_SHA384 => (HASH_ALGORITHM_SHA2_384, cipher::sha384(), cipher::PKEY_KIND_RSA),
            ASN1_RSA_SHA512 => (HASH_ALGORITHM_SHA2_512, cipher::sha512(), cipher::PKEY_KIND_RSA),
            ASN1_ECDSA_SHA256 => (HASH_ALGORITHM_SHA2_256, cipher::sha256(), cipher::PKEY_KIND_EC),
            ASN1_ECDSA_SHA384 => (HASH_ALGORITHM_SHA2_384, cipher::sha384(), cipher::PKEY_KIND_EC),
            ASN1_ECDSA_SHA512 => (HASH_ALGORITHM_SHA2_512, cipher::sha512(), cipher::PKEY_KIND_EC),
            _ => bail!("unsupported AUTH method 14 AlgorithmIdentifier"),
        };

        Ok(ParsedSignatureAuth { hash_algorithm, hash, public_key_type, signature })
    }
}

fn insecure_skip_peer_cert_chain_verify() -> bool {
    std::env::var_os(SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY).is_some_and(|value| {
        value.to_str().is_some_and(|raw| {
            matches!(raw.trim(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
        })
    })
}
