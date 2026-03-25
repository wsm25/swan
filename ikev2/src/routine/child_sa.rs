use anyhow::{Context, Result, bail, ensure};
use bytemuck::pod_read_unaligned;
use bytes::Bytes;

use super::Ikev2Routine;
use crate::{
    ActiveChildSa, ChildSaInstall, ChildSaKeyMaterial, IkeSaState, UdpConn,
    consts::{
        NOTIFY_TYPE_FAILED_CP_REQUIRED, NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE,
        NOTIFY_TYPE_NO_ADDITIONAL_SAS, NOTIFY_TYPE_NO_PROPOSAL_CHOSEN,
        NOTIFY_TYPE_SINGLE_PAIR_REQUIRED, NOTIFY_TYPE_TS_UNACCEPTABLE,
    },
    payload::{
        IkeMessageBuilder, PAYLOAD_TYPE_AUTH, PAYLOAD_TYPE_CERT, PAYLOAD_TYPE_CP, PAYLOAD_TYPE_EAP,
        PAYLOAD_TYPE_IDI, PAYLOAD_TYPE_IDR, PAYLOAD_TYPE_NOTIFY, PAYLOAD_TYPE_SA, PAYLOAD_TYPE_TSI,
        PAYLOAD_TYPE_TSR, Payload,
    },
};
use bytes::BytesMut;

const PROTOCOL_ID_ESP: u8 = 3;
const TRAFFIC_SELECTOR_PAYLOAD_HEADER_LEN: usize = 4;
const TRAFFIC_SELECTOR_HEADER_LEN: usize = 8;
const TRAFFIC_SELECTOR_START_PORT_ANY: u16 = 0;
const TRAFFIC_SELECTOR_END_PORT_ANY: u16 = u16::MAX;

struct ParsedTrafficSelector {
    ts_type: u8,
    start_addr: Box<[u8]>,
    end_addr: Box<[u8]>,
}

impl Ikev2Routine {
    pub(super) async fn finish_auth(
        &mut self,
        udp_conn: &mut dyn UdpConn,
    ) -> Result<ChildSaInstall> {
        self.sa.state = IkeSaState::ChildSaInstalling;
        let message_id = self.sa.next_request_message_id;
        let request = self.build_final_auth_request(message_id)?;
        let (_, payloads) = self
            .run_protected_request(
                udp_conn,
                "final_ike_auth",
                crate::consts::EXCHANGE_TYPE_IKE_AUTH,
                request,
            )
            .await?;
        let child_sa = self.process_final_ike_auth_response(payloads)?;

        ensure!(self.sa.auth.local_eap_msk.is_some(), "eap did not produce keying material");
        ensure!(
            self.sa.assigned_config.is_some(),
            "routine completed without assigned configuration"
        );
        Ok(child_sa)
    }

    fn process_final_ike_auth_response(
        &mut self,
        payloads: Vec<Payload>,
    ) -> Result<ChildSaInstall> {
        let mut inbound_auth = None;
        let mut inbound_idr = None;
        let mut inbound_eap = None;
        let mut inbound_certs = Vec::new();
        let mut child_sa = None;
        let mut tsi = None;
        let mut tsr = None;
        let mut cp = None;
        let mut notify_types = Vec::new();
        let mut child_notifies = Vec::new();

        for payload in payloads {
            match payload.payload_type {
                PAYLOAD_TYPE_AUTH => inbound_auth = Some(payload.body),
                PAYLOAD_TYPE_IDR => inbound_idr = Some(payload.body),
                PAYLOAD_TYPE_EAP => inbound_eap = Some(payload.body),
                PAYLOAD_TYPE_CERT => inbound_certs.push(payload.body),
                PAYLOAD_TYPE_SA => child_sa = Some(payload.body),
                PAYLOAD_TYPE_TSI => tsi = Some(payload.body),
                PAYLOAD_TYPE_TSR => tsr = Some(payload.body),
                PAYLOAD_TYPE_CP => cp = Some(payload.body),
                PAYLOAD_TYPE_NOTIFY => {
                    let notify = Self::decode_notify_payload(payload.body.as_ref())?;
                    ensure!(
                        notify.spi.is_empty() || notify.spi.len() == 4,
                        "unexpected SPI size in final IKE_AUTH notify"
                    );
                    if !notify.spi.is_empty() {
                        ensure!(
                            matches!(
                                notify.notify_type,
                                NOTIFY_TYPE_NO_PROPOSAL_CHOSEN
                                    | NOTIFY_TYPE_SINGLE_PAIR_REQUIRED
                                    | NOTIFY_TYPE_NO_ADDITIONAL_SAS
                                    | NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE
                                    | NOTIFY_TYPE_TS_UNACCEPTABLE
                                    | NOTIFY_TYPE_FAILED_CP_REQUIRED
                            ),
                            "unexpected SPI-scoped notify in final IKE_AUTH"
                        );
                        child_notifies.push((
                            notify.notify_type,
                            notify.protocol_id,
                            u32::from_be_bytes(notify.spi.try_into().unwrap()),
                        ));
                    }
                    notify_types.push(notify.notify_type);
                }
                _ => {}
            }
        }

        self.validate_ike_auth_notifies(&notify_types)?;
        ensure!(inbound_eap.is_none(), "final IKE_AUTH response must not include EAP payload");

        let peer_idr = inbound_idr.or_else(|| self.sa.auth.peer_idr_payload.clone());
        let peer_idr = peer_idr.context("final IKE_AUTH response missing IDr payload")?;
        self.record_peer_identity(peer_idr.clone())?;
        if !inbound_certs.is_empty() {
            let mut cert_chain = Vec::with_capacity(inbound_certs.len());
            for payload in inbound_certs {
                let (encoding, cert_der) = Self::decode_cert_payload(payload.as_ref())?;
                ensure!(
                    encoding == super::common::CERT_ENCODING_X509_SIGNATURE,
                    "unsupported CERT encoding {encoding}"
                );
                cert_chain.push(Bytes::copy_from_slice(cert_der));
            }
            self.sa.auth.peer_cert_der = cert_chain.first().cloned();
            self.sa.auth.peer_cert_chain = cert_chain;
        }

        if let Some(auth_payload) = inbound_auth {
            self.sa.auth.peer_auth_method =
                Some(self.verify_peer_auth_payload(peer_idr.as_ref(), auth_payload.as_ref())?);
        } else {
            bail!("final IKE_AUTH response missing AUTH payload");
        }

        let child_sa = if let Some(child_sa) = child_sa {
            child_sa
        } else if let Some(reason) = Self::ike_auth_child_failure_reason(notify_types.as_slice()) {
            bail!("CHILD_SA negotiation failed: {reason}");
        } else {
            bail!("final IKE_AUTH response missing CHILD_SA proposal");
        };

        let (peer_selected_spi, child_selection) =
            self.decode_child_sa_selection(child_sa.as_ref())?;
        let local_inbound_spi = self
            .sa
            .negotiating_child_sa
            .as_ref()
            .context("missing negotiating CHILD_SA state")?
            .inbound_spi;
        self.validate_final_ike_auth_child_notifies(
            child_notifies.as_slice(),
            local_inbound_spi,
            peer_selected_spi,
        )?;
        self.selected_child_suite = Some(child_selection.clone());
        self.emit_negotiated_esp_algorithms()?;

        let assigned_config = if let Some(cp) = cp {
            self.decode_assigned_config(cp.as_ref())?
        } else {
            bail!("final IKE_AUTH response missing CP payload");
        };
        ensure!(
            assigned_config.internal_ipv4.is_some() || assigned_config.internal_ipv6.is_some(),
            "final IKE_AUTH CP reply missing INTERNAL_IP4_ADDRESS/INTERNAL_IP6_ADDRESS"
        );
        let tsi = tsi.context("final IKE_AUTH response missing TSi payload")?;
        let tsr = tsr.context("final IKE_AUTH response missing TSr payload")?;
        self.validate_remote_access_traffic_selectors(
            tsi.as_ref(),
            tsr.as_ref(),
            &assigned_config,
        )?;
        self.sa.assigned_config = Some(assigned_config);

        let install_for_state = ChildSaInstall {
            inbound_spi: local_inbound_spi,
            outbound_spi: peer_selected_spi,
            tsi: tsi.clone(),
            tsr: tsr.clone(),
        };
        self.sa.negotiating_child_sa = None;
        self.sa.active_child_sa = Some(ActiveChildSa { install: install_for_state });
        Ok(ChildSaInstall {
            inbound_spi: local_inbound_spi,
            outbound_spi: peer_selected_spi,
            tsi,
            tsr,
        })
    }

    pub(crate) fn derive_child_sa_key_material(&self) -> Result<ChildSaKeyMaterial> {
        let keys = self.sa.key_material.as_ref().context("IKE key material is missing")?;
        let initiator_nonce =
            self.sa.initiator_nonce.as_ref().context("initiator nonce missing")?;
        let responder_nonce =
            self.sa.responder_nonce.as_ref().context("responder nonce missing")?;
        let selection = self.selected_esp_proposal()?;
        let ike_prf = self.selected_ike_proposal()?.prf;
        let integ_len = if selection.encryption.is_aead {
            0
        } else {
            selection.integrity.key_len_hint
        };
        ensure!(selection.encryption.key_len > 0, "unsupported CHILD_SA encryption key length");
        ensure!(
            selection.encryption.is_aead || integ_len > 0,
            "unsupported CHILD_SA integrity key length"
        );

        let mut seed = Vec::with_capacity(initiator_nonce.len() + responder_nonce.len());
        seed.extend_from_slice(initiator_nonce.as_ref());
        seed.extend_from_slice(responder_nonce.as_ref());
        let out_len = 2 * (selection.encryption.key_len + integ_len);
        let keymat = Self::prf_plus(ike_prf, keys.sk_d.as_ref(), seed.as_ref(), out_len)?;

        let mut offset = 0usize;
        let sk_ei =
            keymat[offset..offset + selection.encryption.key_len].to_vec().into_boxed_slice();
        offset += selection.encryption.key_len;
        let sk_ai = keymat[offset..offset + integ_len].to_vec().into_boxed_slice();
        offset += integ_len;
        let sk_er =
            keymat[offset..offset + selection.encryption.key_len].to_vec().into_boxed_slice();
        offset += selection.encryption.key_len;
        let sk_ar = keymat[offset..offset + integ_len].to_vec().into_boxed_slice();

        Ok(ChildSaKeyMaterial { sk_ei, sk_ai, sk_er, sk_ar })
    }

    fn build_final_auth_request(&self, message_id: u32) -> Result<Vec<bytes::Bytes>> {
        let local =
            self.local_identity.as_ref().context("local identity missing before final AUTH")?;
        let auth_payload = self.build_local_auth_payload(local.id_type, local.value.as_ref())?;
        let mut inner = IkeMessageBuilder::new(BytesMut::with_capacity(128));
        if let Some(rightid) = self.expected_rightid() {
            let (id_type, id_value) = Self::configured_id_type_and_value(rightid);
            let id_value = id_value.as_bytes();
            inner.push_payload(PAYLOAD_TYPE_IDR, false, |buf| {
                Self::append_id_payload_typed(buf, id_type, id_value)
            });
        }
        let idi_payload =
            self.sa.auth.first_idi_payload.clone().unwrap_or_else(|| {
                Self::build_id_payload_typed(local.id_type, local.value.as_ref())
            });
        inner.push_payload(PAYLOAD_TYPE_IDI, false, |buf| {
            buf.extend_from_slice(idi_payload.as_ref())
        });
        inner.push_payload(PAYLOAD_TYPE_AUTH, false, |buf| {
            buf.extend_from_slice(auth_payload.as_ref())
        });
        self.build_protected_request(message_id, inner)
    }

    fn validate_final_ike_auth_child_notifies(
        &self,
        notifies: &[(u16, u8, u32)],
        expected_outbound_spi: u32,
        inbound_spi: u32,
    ) -> Result<()> {
        for (notify_type, protocol_id, spi) in notifies {
            ensure!(
                *protocol_id == PROTOCOL_ID_ESP,
                "unexpected SPI-scoped notify protocol in final IKE_AUTH"
            );
            ensure!(
                *spi == expected_outbound_spi || *spi == inbound_spi,
                "unexpected SPI-scoped notify SPI in final IKE_AUTH for notify {notify_type}"
            );
        }
        Ok(())
    }

    fn ike_auth_child_failure_reason(notifies: &[u16]) -> Option<&'static str> {
        [
            (NOTIFY_TYPE_NO_PROPOSAL_CHOSEN, "NO_PROPOSAL_CHOSEN"),
            (NOTIFY_TYPE_SINGLE_PAIR_REQUIRED, "SINGLE_PAIR_REQUIRED"),
            (NOTIFY_TYPE_NO_ADDITIONAL_SAS, "NO_ADDITIONAL_SAS"),
            (NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE, "INTERNAL_ADDRESS_FAILURE"),
            (NOTIFY_TYPE_FAILED_CP_REQUIRED, "FAILED_CP_REQUIRED"),
            (NOTIFY_TYPE_TS_UNACCEPTABLE, "TS_UNACCEPTABLE"),
        ]
        .into_iter()
        .find_map(|(notify_type, reason)| notifies.contains(&notify_type).then_some(reason))
    }

    fn validate_remote_access_traffic_selectors(
        &self,
        tsi_payload: &[u8],
        tsr_payload: &[u8],
        assigned_config: &crate::AssignedConfig,
    ) -> Result<()> {
        let tsi = Self::decode_traffic_selectors(tsi_payload, "TSi")?;
        let tsr = Self::decode_traffic_selectors(tsr_payload, "TSr")?;
        ensure!(!tsi.is_empty(), "final IKE_AUTH response missing TSi selectors");
        ensure!(!tsr.is_empty(), "final IKE_AUTH response missing TSr selectors");

        for tsi in &tsi {
            match tsi.ts_type {
                super::common::TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE => {
                    let assigned = assigned_config
                        .internal_ipv4
                        .context("final IKE_AUTH TSi is IPv4 but CP has no INTERNAL_IP4_ADDRESS")?;
                    ensure!(tsi.start_addr.len() == 4, "invalid IPv4 TSi address length");
                    ensure!(tsi.end_addr.len() == 4, "invalid IPv4 TSi address length");
                    ensure!(
                        tsi.start_addr.as_ref() == assigned.as_slice()
                            && tsi.end_addr.as_ref() == assigned.as_slice(),
                        "final IKE_AUTH TSi must narrow to the assigned INTERNAL_IP4_ADDRESS"
                    );
                }
                super::common::TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE => {
                    let assigned = assigned_config
                        .internal_ipv6
                        .context("final IKE_AUTH TSi is IPv6 but CP has no INTERNAL_IP6_ADDRESS")?;
                    ensure!(tsi.start_addr.len() == 16, "invalid IPv6 TSi address length");
                    ensure!(tsi.end_addr.len() == 16, "invalid IPv6 TSi address length");
                    ensure!(
                        tsi.start_addr.as_ref() == assigned.as_slice()
                            && tsi.end_addr.as_ref() == assigned.as_slice(),
                        "final IKE_AUTH TSi must narrow to the assigned INTERNAL_IP6_ADDRESS"
                    );
                }
                other => bail!("unsupported final IKE_AUTH traffic selector type {other}"),
            }
        }

        for tsr in &tsr {
            match tsr.ts_type {
                super::common::TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE => {
                    ensure!(
                        tsr.start_addr.len() == 4 && tsr.end_addr.len() == 4,
                        "invalid IPv4 TSr address length"
                    );
                }
                super::common::TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE => {
                    ensure!(
                        tsr.start_addr.len() == 16 && tsr.end_addr.len() == 16,
                        "invalid IPv6 TSr address length"
                    );
                }
                other => bail!("unsupported final IKE_AUTH traffic selector type {other}"),
            }
            ensure!(
                tsr.start_addr.as_ref() <= tsr.end_addr.as_ref(),
                "final IKE_AUTH TSr address range is invalid"
            );
        }
        Ok(())
    }

    fn decode_traffic_selectors(
        payload: &[u8],
        payload_name: &str,
    ) -> Result<Vec<ParsedTrafficSelector>> {
        ensure!(
            payload.len() >= TRAFFIC_SELECTOR_PAYLOAD_HEADER_LEN,
            "{payload_name} payload is too short"
        );
        let payload_header = pod_read_unaligned::<super::common::TrafficSelectorPayloadHeader>(
            &payload[..TRAFFIC_SELECTOR_PAYLOAD_HEADER_LEN],
        );
        ensure!(
            payload_header.count > 0,
            "{payload_name} must contain at least one traffic selector"
        );
        let mut selectors = Vec::with_capacity(payload_header.count as usize);
        let mut rest = &payload[TRAFFIC_SELECTOR_PAYLOAD_HEADER_LEN..];
        for _ in 0..payload_header.count {
            ensure!(
                rest.len() >= TRAFFIC_SELECTOR_HEADER_LEN,
                "{payload_name} selector is too short"
            );
            let header = pod_read_unaligned::<super::common::TrafficSelectorHeader>(
                &rest[..TRAFFIC_SELECTOR_HEADER_LEN],
            );
            ensure!(header.ip_protocol_id == 0, "{payload_name} must use protocol 0 for MVP");
            ensure!(
                header.start_port.to_native() == TRAFFIC_SELECTOR_START_PORT_ANY
                    && header.end_port.to_native() == TRAFFIC_SELECTOR_END_PORT_ANY,
                "{payload_name} must allow all ports for MVP"
            );
            let addr_len = match header.ts_type {
                super::common::TRAFFIC_SELECTOR_TYPE_IPV4_ADDR_RANGE => 4,
                super::common::TRAFFIC_SELECTOR_TYPE_IPV6_ADDR_RANGE => 16,
                other => bail!("unsupported {payload_name} traffic selector type {other}"),
            };
            let selector_length = header.selector_length.to_native() as usize;
            ensure!(
                selector_length == TRAFFIC_SELECTOR_HEADER_LEN + (addr_len * 2),
                "{payload_name} has invalid traffic selector length"
            );
            ensure!(rest.len() >= selector_length, "{payload_name} selector overruns payload");
            let selector = &rest[..selector_length];
            let addresses = &selector[TRAFFIC_SELECTOR_HEADER_LEN..];
            let start_addr = addresses[..addr_len].to_vec().into_boxed_slice();
            let end_addr = addresses[addr_len..].to_vec().into_boxed_slice();
            ensure!(
                start_addr.as_ref() <= end_addr.as_ref(),
                "{payload_name} address range is invalid"
            );
            selectors.push(ParsedTrafficSelector { ts_type: header.ts_type, start_addr, end_addr });
            rest = &rest[selector_length..];
        }
        ensure!(
            rest.is_empty(),
            "{payload_name} must not contain trailing bytes after traffic selectors"
        );
        Ok(selectors)
    }
}
