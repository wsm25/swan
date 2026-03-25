use anyhow::{Context, Result, bail, ensure};
use bytemuck::{Pod, Zeroable, bytes_of};
use bytes::Bytes;
use hex_literal::hex;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::sign::Verifier;
use openssl::ssl::SslFiletype;
use openssl::stack::Stack;
use openssl::x509::store::{X509Lookup, X509StoreBuilder};
use openssl::x509::{X509, X509StoreContext};

use super::{
    Ikev2Routine, PeerIdentity,
    common::ParsedSignatureAuth,
    ids::rightid_matches,
};
use crate::consts::{
    ID_TYPE_DER_ASN1_DN, ID_TYPE_FQDN, ID_TYPE_IPV4_ADDR, ID_TYPE_IPV6_ADDR, ID_TYPE_KEY_ID,
    ID_TYPE_RFC822_ADDR, NOTIFY_TYPE_ADDITIONAL_TS_POSSIBLE, NOTIFY_TYPE_AUTHENTICATION_FAILED,
    NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION, NOTIFY_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED,
    NOTIFY_TYPE_FAILED_CP_REQUIRED, NOTIFY_TYPE_FRAGMENTATION_SUPPORTED,
    NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC, NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED,
    NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE, NOTIFY_TYPE_IPCOMP_SUPPORTED,
    NOTIFY_TYPE_NO_ADDITIONAL_SAS, NOTIFY_TYPE_NO_PROPOSAL_CHOSEN,
    NOTIFY_TYPE_NON_FIRST_FRAGMENTS_ALSO, NOTIFY_TYPE_SINGLE_PAIR_REQUIRED,
    NOTIFY_TYPE_TS_UNACCEPTABLE, NOTIFY_TYPE_USE_TRANSPORT_MODE,
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
const SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY: &str =
    "SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY";

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
        let key = (selection.prf.gen_prf)(auth_secret, IKEV2_KEY_PAD)
            .context("compute responder AUTH key")?;
        crate::debug_fmt::log_auth_bytes("peer AUTH keypad prf =>", key.as_ref());
        let mac =
            (selection.prf.gen_prf)(&key, octets.as_ref()).context("compute responder AUTH MAC")?;
        Ok(Bytes::from(mac))
    }

    fn compute_local_auth_mac(&self, idi_payload: &[u8]) -> Result<Bytes> {
        let octets = self.compute_local_signed_octets(idi_payload)?;
        crate::debug_fmt::log_auth_bytes("local AUTH octets =>", octets.as_ref());
        let keys = self.sa.key_material.as_ref().context("IKE key material is missing")?;
        let selection = self.selected_ike_proposal()?;
        let auth_secret = self.sa.auth.local_eap_msk.as_deref().unwrap_or(keys.sk_pi.as_ref());
        crate::debug_fmt::log_auth_bytes("local AUTH secret =>", auth_secret);
        let key = (selection.prf.gen_prf)(auth_secret, IKEV2_KEY_PAD)
            .context("compute initiator AUTH key")?;
        crate::debug_fmt::log_auth_bytes("local AUTH keypad prf =>", key.as_ref());
        let mac =
            (selection.prf.gen_prf)(&key, octets.as_ref()).context("compute initiator AUTH MAC")?;
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
        let maced_id = (selection.prf.gen_prf)(keys.sk_pr.as_ref(), idr_payload)
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
        let maced_id = (selection.prf.gen_prf)(keys.sk_pi.as_ref(), idi_payload)
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
        let certs = self.peer_x509_cert_chain()?;
        let leaf = certs.first().context("missing responder certificate for AUTH")?;
        self.verify_peer_certificate_chain(&certs)?;
        self.verify_peer_certificate_identity(leaf, idr_payload)?;
        let public_key = leaf.public_key().context("extract responder certificate public key")?;
        let digest = match auth_method {
            AUTH_METHOD_RSA_DIGITAL_SIGNATURE | AUTH_METHOD_DSS_DIGITAL_SIGNATURE => {
                MessageDigest::sha1()
            }
            _ => bail!("unsupported signature AUTH method {auth_method}"),
        };
        let mut verifier =
            Verifier::new(digest, &public_key).context("initialize AUTH signature verifier")?;
        verifier.update(octets).context("update AUTH signature verifier")?;
        ensure!(
            verifier.verify(signature).context("finalize AUTH signature verifier")?,
            "AUTH signature verification failed"
        );
        Ok(())
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

        let certs = self.peer_x509_cert_chain()?;
        let leaf = certs.first().context("missing responder certificate for AUTH")?;
        self.verify_peer_certificate_chain(&certs)?;
        self.verify_peer_certificate_identity(leaf, idr_payload)?;
        let public_key = leaf.public_key().context("extract responder certificate public key")?;
        ensure!(
            public_key.id() == parsed.public_key_type,
            "AUTH method 14 algorithm does not match responder certificate key type"
        );

        let mut verifier = Verifier::new(parsed.digest, &public_key)
            .context("initialize AUTH method 14 signature verifier")?;
        verifier.update(octets).context("update AUTH method 14 signature verifier")?;
        ensure!(
            verifier
                .verify(parsed.signature)
                .context("finalize AUTH method 14 signature verifier")?,
            "AUTH signature verification failed"
        );
        Ok(())
    }

    fn peer_x509_cert_chain(&self) -> Result<Vec<X509>> {
        let certs = if self.sa.auth.peer_cert_chain.is_empty() {
            self.sa.auth.peer_cert_der.clone().into_iter().collect::<Vec<_>>()
        } else {
            self.sa.auth.peer_cert_chain.clone()
        };
        ensure!(
            !certs.is_empty(),
            "responder AUTH used certificate signature without CERT payload"
        );
        certs
            .into_iter()
            .map(|cert| X509::from_der(cert.as_ref()).context("parse responder X509 certificate"))
            .collect()
    }

    fn verify_peer_certificate_chain(&self, certs: &[X509]) -> Result<()> {
        if insecure_skip_peer_cert_chain_verify() {
            return Ok(());
        }
        let leaf = certs.first().context("missing responder leaf certificate")?;
        let mut chain = Stack::new().context("allocate responder certificate chain")?;
        for cert in &certs[1..] {
            chain.push(cert.to_owned()).context("append responder certificate chain entry")?;
        }
        let mut store = X509StoreBuilder::new().context("create X509 trust store")?;
        store.set_default_paths().context("load default X509 trust store")?;
        store
            .add_lookup(X509Lookup::file())
            .context("add X509 file lookup for /etc/ssl/cert.pem")?
            .load_cert_file("/etc/ssl/cert.pem", SslFiletype::PEM)
            .context("load /etc/ssl/cert.pem X509 trust store")?;
        let store = store.build();
        let mut context = X509StoreContext::new().context("create X509 store context")?;
        let verified = context
            .init(&store, leaf, &chain, |ctx| ctx.verify_cert())
            .context("verify responder certificate chain")?;
        ensure!(verified, "responder certificate chain verification failed");
        Ok(())
    }

    fn verify_peer_certificate_identity(&self, leaf: &X509, idr_payload: &[u8]) -> Result<()> {
        ensure!(
            idr_payload.len() >= super::common::ID_PAYLOAD_FIXED_FIELDS_LEN,
            "invalid IDr payload for certificate identity verification"
        );
        let id_type = idr_payload[0];
        let id_value = &idr_payload[super::common::ID_PAYLOAD_FIXED_FIELDS_LEN..];
        match id_type {
            ID_TYPE_FQDN => {
                let expected =
                    std::str::from_utf8(id_value).context("IDr FQDN is not valid UTF-8")?;
                ensure!(
                    Self::certificate_matches_dns_name(leaf, expected),
                    "responder certificate does not match IDr FQDN {expected}"
                );
            }
            ID_TYPE_RFC822_ADDR => {
                let expected = std::str::from_utf8(id_value)
                    .context("IDr RFC822 address is not valid UTF-8")?;
                ensure!(
                    Self::certificate_matches_rfc822_name(leaf, expected),
                    "responder certificate does not match IDr RFC822 address {expected}"
                );
            }
            ID_TYPE_IPV4_ADDR | ID_TYPE_IPV6_ADDR => {
                ensure!(
                    Self::certificate_matches_ip_address(leaf, id_value),
                    "responder certificate does not match IDr IP address"
                );
            }
            ID_TYPE_DER_ASN1_DN => {
                let subject_name_der = leaf
                    .subject_name()
                    .to_der()
                    .context("encode responder certificate subject name")?;
                ensure!(
                    subject_name_der.as_slice() == id_value,
                    "responder certificate subject name does not match IDr"
                );
            }
            ID_TYPE_KEY_ID => {
                // TODO: accept ID_KEY_ID for broader RFC 7296 PKIX interoperability.
                bail!("certificate identity verification does not support KEY_ID IDr for MVP");
            }
            other => bail!("unsupported IDr type {other} for certificate identity verification"),
        }
        Ok(())
    }

    fn certificate_matches_dns_name(cert: &X509, expected: &str) -> bool {
        if cert.subject_alt_names().is_some_and(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname())
                .any(|dns_name| dns_name.eq_ignore_ascii_case(expected))
        }) {
            return true;
        }
        cert.subject_name().entries_by_nid(Nid::COMMONNAME).any(|entry| {
            entry.data().as_utf8().ok().is_some_and(|value| value.eq_ignore_ascii_case(expected))
        })
    }

    fn certificate_matches_rfc822_name(cert: &X509, expected: &str) -> bool {
        cert.subject_alt_names().is_some_and(|names| {
            names
                .iter()
                .filter_map(|name| name.email())
                .any(|email| email.eq_ignore_ascii_case(expected))
        })
    }

    fn certificate_matches_ip_address(cert: &X509, expected: &[u8]) -> bool {
        cert.subject_alt_names().is_some_and(|names| {
            names
                .iter()
                .filter_map(|name| name.ipaddress())
                .any(|ip_address| ip_address == expected)
        })
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

        let (hash_algorithm, digest, public_key_type) = match algorithm_identifier {
            ASN1_RSA_SHA256 => {
                (HASH_ALGORITHM_SHA2_256, MessageDigest::sha256(), openssl::pkey::Id::RSA)
            }
            ASN1_RSA_SHA384 => {
                (HASH_ALGORITHM_SHA2_384, MessageDigest::sha384(), openssl::pkey::Id::RSA)
            }
            ASN1_RSA_SHA512 => {
                (HASH_ALGORITHM_SHA2_512, MessageDigest::sha512(), openssl::pkey::Id::RSA)
            }
            ASN1_ECDSA_SHA256 => {
                (HASH_ALGORITHM_SHA2_256, MessageDigest::sha256(), openssl::pkey::Id::EC)
            }
            ASN1_ECDSA_SHA384 => {
                (HASH_ALGORITHM_SHA2_384, MessageDigest::sha384(), openssl::pkey::Id::EC)
            }
            ASN1_ECDSA_SHA512 => {
                (HASH_ALGORITHM_SHA2_512, MessageDigest::sha512(), openssl::pkey::Id::EC)
            }
            _ => bail!("unsupported AUTH method 14 AlgorithmIdentifier"),
        };

        Ok(ParsedSignatureAuth { hash_algorithm, digest, public_key_type, signature })
    }
}

fn insecure_skip_peer_cert_chain_verify() -> bool {
    std::env::var_os(SWAN_INSECURE_SKIP_PEER_CERT_CHAIN_VERIFY).is_some_and(|value| {
        value.to_str().is_some_and(|raw| {
            matches!(raw.trim(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
        })
    })
}
