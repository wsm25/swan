use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use bytes::Bytes;

use super::{Ikev2Routine, UdpConn};
use crate::{
    IkeSaState,
    consts::{
        NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION, NOTIFY_TYPE_FRAGMENTATION_SUPPORTED,
        NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED,
    },
    eap::{EapPeer, EapRunResult},
    payload::{
        PAYLOAD_TYPE_AUTH, PAYLOAD_TYPE_CERT, PAYLOAD_TYPE_EAP, PAYLOAD_TYPE_IDR,
        PAYLOAD_TYPE_NOTIFY, Payload,
    },
};

struct RoutineEapPeer<'a> {
    routine: &'a mut Ikev2Routine,
    udp_conn: &'a mut dyn UdpConn,
    first_response: bool,
}

#[async_trait]
impl EapPeer for RoutineEapPeer<'_> {
    async fn recv_request(&mut self) -> Result<Bytes> {
        let expected = self
            .routine
            .sa
            .expected_response_message_id
            .context("missing expected IKE_AUTH response message-id")?;
        let payloads = self
            .routine
            .recv_response_protected(
                self.udp_conn,
                "eap",
                crate::consts::EXCHANGE_TYPE_IKE_AUTH,
                expected,
            )
            .await?;
        let request =
            self.routine.process_ike_auth_response_payloads(payloads, self.first_response)?;
        self.routine.emit_eap_process("request", Some(expected as u16));
        self.first_response = false;
        Ok(request)
    }

    async fn send_response(&mut self, packet: Bytes) -> Result<()> {
        let message_id = self.routine.sa.next_request_message_id;
        let packets = self.routine.build_single_protected_payload_packets(
            message_id,
            PAYLOAD_TYPE_EAP,
            packet.as_ref(),
        )?;
        self.routine.begin_request_exchange();
        self.routine.send_request_packets(self.udp_conn, message_id, packets).await?;
        self.routine.emit_eap_process("response", Some(message_id as u16));
        Ok(())
    }

    fn next_round_index(&self) -> u16 {
        self.routine.sa.next_request_message_id as u16
    }
}

impl Ikev2Routine {
    pub(super) async fn run_eap(&mut self, udp_conn: &mut dyn UdpConn) -> Result<()> {
        self.sa.state = IkeSaState::IkeAuthEapInProgress;
        let mut eap_method = self.eap_method.clone();
        self.emit_event(crate::Ikev2Event::EapProcess(crate::Ikev2EapProcess {
            method: eap_method.name().into(),
            state: "started",
            round: None,
        }));
        let mut peer = RoutineEapPeer { routine: self, udp_conn, first_response: true };
        let result = eap_method.run(&mut peer).await;
        peer.routine.eap_method = eap_method;
        let EapRunResult { exported_msk } = result?;
        peer.routine.sa.auth.local_eap_msk = Some(exported_msk);
        peer.routine.emit_eap_process("completed", None);
        Ok(())
    }

    pub(super) fn process_ike_auth_response_payloads(
        &mut self,
        payloads: Vec<Payload>,
        first_response: bool,
    ) -> Result<Bytes> {
        let mut inbound_eap = None;
        let mut inbound_auth = None;
        let mut inbound_idr = None;
        let mut inbound_certs = Vec::new();
        let mut notify_types = Vec::new();

        for payload in payloads {
            match payload.payload_type {
                PAYLOAD_TYPE_EAP => inbound_eap = Some(payload.body),
                PAYLOAD_TYPE_AUTH => inbound_auth = Some(payload.body),
                PAYLOAD_TYPE_IDR => inbound_idr = Some(payload.body),
                PAYLOAD_TYPE_CERT => inbound_certs.push(payload.body),
                PAYLOAD_TYPE_NOTIFY => {
                    let notify = Self::decode_notify_payload(payload.body.as_ref())?;
                    ensure!(
                        notify.spi.is_empty(),
                        "unexpected SPI-scoped notify during EAP progression"
                    );
                    notify_types.push(notify.notify_type);
                }
                _ => {}
            }
        }

        self.validate_ike_auth_notifies(&notify_types)?;
        self.sa.peer.supports_eap_only_authentication =
            notify_types.contains(&NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION);
        self.sa.peer.supports_message_id_sync =
            notify_types.contains(&NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED);
        self.sa.peer.supports_fragmentation |=
            notify_types.contains(&NOTIFY_TYPE_FRAGMENTATION_SUPPORTED);

        let peer_idr = inbound_idr.or_else(|| self.sa.auth.peer_idr_payload.clone());
        let peer_idr = peer_idr.context("IKE_AUTH response missing IDr payload")?;
        self.record_peer_identity(peer_idr.clone())?;
        self.sa.auth.peer_idr_payload = Some(peer_idr.clone());
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

        if first_response {
            if let Some(auth_payload) = inbound_auth.as_ref() {
                self.sa.auth.peer_auth_method =
                    Some(self.verify_peer_auth_payload(peer_idr.as_ref(), auth_payload.as_ref())?);
            } else {
                ensure!(inbound_eap.is_some(), "first IKE_AUTH response missing AUTH payload");
                ensure!(
                    self.sa.peer.supports_eap_only_authentication,
                    "configured EAP-only authentication, but peer does not support it"
                );
            }
        } else if let Some(auth_payload) = inbound_auth.as_ref() {
            self.sa.auth.peer_auth_method =
                Some(self.verify_peer_auth_payload(peer_idr.as_ref(), auth_payload.as_ref())?);
        }

        inbound_eap.context("IKE_AUTH response missing EAP payload")
    }
}
