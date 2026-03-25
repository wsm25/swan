use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};

use super::{Ikev2Routine, PeerIdentity, UdpConn};
use crate::{
    IkeSaState, NegotiatingChildSa,
    consts::{
        NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION, NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED,
        NOTIFY_TYPE_INITIAL_CONTACT, NOTIFY_TYPE_MOBIKE_SUPPORTED,
        NOTIFY_TYPE_MULTIPLE_AUTH_SUPPORTED, NOTIFY_TYPE_NO_ADDITIONAL_ADDRESSES,
    },
    eap::{EapMethodConfig, build_method},
    payload::{
        IkeMessageBuilder, PAYLOAD_TYPE_CP, PAYLOAD_TYPE_IDI, PAYLOAD_TYPE_IDR,
        PAYLOAD_TYPE_NOTIFY, PAYLOAD_TYPE_SA, PAYLOAD_TYPE_TSI, PAYLOAD_TYPE_TSR,
    },
};

impl Ikev2Routine {
    pub(super) async fn start_auth(
        &mut self,
        udp_conn: &mut dyn UdpConn,
    ) -> Result<()> {
        self.sa.state = IkeSaState::IkeAuthBootstrap;
        self.eap_method = build_method(EapMethodConfig {
            peer_identity: self.config.eap_identity.clone(),
            peer_password: self.config.eap_password.clone(),
            aaa_identity: self.config.aaa_identity.clone(),
            method_name: self.config.eap_method.clone(),
            peap_fragment_size: self.config.peap_fragment_size,
            peap_max_message_count: self.config.peap_max_message_count,
            peap_include_length: self.config.peap_include_length,
            peap_tls13_strongswan_compat: self.config.peap_tls13_strongswan_compat,
        })?;

        let message_id = self.sa.next_request_message_id;
        let request = self.build_initial_ike_auth_request(message_id)?;
        self.begin_request_exchange();
        self.send_request_packets(udp_conn, message_id, request).await?;
        self.sa.state = IkeSaState::IkeAuthEapInProgress;
        Ok(())
    }

    fn build_initial_ike_auth_request(&mut self, message_id: u32) -> Result<Vec<Bytes>> {
        let (idi_type, idi_value) =
            Self::configured_id_type_and_value(self.config.idi.as_str());
        let idi_value = Self::encoded_id_value(idi_type, idi_value)?;
        let idi = Self::build_id_payload_typed(idi_type, idi_value.as_ref());
        self.sa.auth.first_idi_payload = Some(idi.clone());
        self.local_identity =
            Some(PeerIdentity { id_type: idi_type, value: idi_value.to_vec().into_boxed_slice() });

        let inbound_spi = Self::generate_child_spi()?;
        self.sa.negotiating_child_sa = Some(NegotiatingChildSa { inbound_spi });
        let mut inner = IkeMessageBuilder::new(BytesMut::with_capacity(128));
        inner.push_payload(PAYLOAD_TYPE_IDI, false, |buf| {
            Self::append_id_payload_typed(buf, idi_type, idi_value.as_ref());
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
            Self::append_notify_payload(buf, NOTIFY_TYPE_INITIAL_CONTACT, &[]);
            Ok(())
        })?;
        if let Some(rightid) = self.expected_rightid() {
            let (id_type, id_value) = Self::configured_id_type_and_value(rightid);
            let id_value = Self::encoded_id_value(id_type, id_value)?;
            inner.push_payload(PAYLOAD_TYPE_IDR, false, |buf| {
                Self::append_id_payload_typed(buf, id_type, id_value.as_ref());
                Ok(())
            })?;
        }
        inner.push_payload(PAYLOAD_TYPE_CP, false, |buf| {
            Self::append_cp_request_address_and_dns_requests(buf);
            Ok(())
        })?;
        let esp_suite = self
            .config
            .esp_suite
            .first()
            .context("esp_suite is required for CHILD_SA proposal")?;
        inner.push_payload(PAYLOAD_TYPE_SA, false, |buf| {
            self.append_child_sa_proposal(buf, esp_suite, inbound_spi)
        })?;
        inner.push_payload(PAYLOAD_TYPE_TSI, false, |buf| {
            Self::append_ts_any_dual_stack(buf);
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_TSR, false, |buf| {
            Self::append_tsr_strongswan_default(buf);
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
            Self::append_notify_payload(buf, NOTIFY_TYPE_MOBIKE_SUPPORTED, &[]);
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
            Self::append_notify_payload(buf, NOTIFY_TYPE_NO_ADDITIONAL_ADDRESSES, &[]);
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
            Self::append_notify_payload(buf, NOTIFY_TYPE_MULTIPLE_AUTH_SUPPORTED, &[]);
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
            Self::append_notify_payload(buf, NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION, &[]);
            Ok(())
        })?;
        inner.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
            Self::append_notify_payload(buf, NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED, &[]);
            Ok(())
        })?;

        self.build_protected_request(message_id, inner)
    }
}
