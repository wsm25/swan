use anyhow::{Context, Result, bail, ensure};
use bytes::{Bytes, BytesMut};

use super::{Ikev2Routine, UdpConn};
use crate::{
    IkeKeyMaterial, KeyExchangePayload, PeerCapabilities,
    consts::{
        EXCHANGE_TYPE_IKE_SA_INIT, NOTIFY_TYPE_COOKIE, NOTIFY_TYPE_FRAGMENTATION_SUPPORTED,
        NOTIFY_TYPE_INVALID_KE_PAYLOAD, NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP,
        NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP, NOTIFY_TYPE_NO_PROPOSAL_CHOSEN,
        NOTIFY_TYPE_SIGNATURE_HASH_ALGORITHMS,
    },
    payload::{
        IKE_HEADER_LEN, IkeFlags, IkeHeader, IkeMessageBuilder, PAYLOAD_TYPE_KE,
        PAYLOAD_TYPE_NONCE, PAYLOAD_TYPE_NOTIFY, PAYLOAD_TYPE_SA, Payload,
    },
    routine::common::NotifyHeader,
};
use bytemuck::bytes_of;

impl Ikev2Routine {
    pub(super) async fn run_sa_init(&mut self, udp_conn: &mut dyn UdpConn) -> Result<()> {
        self.sa.state = super::IkeSaState::IkeSaInitSent;
        self.sa.expected_response_message_id = Some(0);
        let mut requested_dh_group = None;

        for attempt in 0..=2 {
            let request = self.build_ike_sa_init_request(requested_dh_group)?;
            self.sa.sa_init_request = Some(request.clone());
            self.send_request_packets(udp_conn, 0, vec![request]).await?;

            let response = self.recv_packet(udp_conn, "ike_sa_init").await?;
            let (header, payloads) =
                self.parse_response_plain(response.clone(), EXCHANGE_TYPE_IKE_SA_INIT, 0)?;

            match self.apply_sa_init_response(header, &payloads)? {
                SaInitOutcome::Established => {
                    self.sa.sa_init_response = Some(response);
                    self.derive_ike_sa_keys()?;
                    self.emit_negotiated_ike_algorithms()?;
                    self.sa.next_request_message_id = 1;
                    self.sa.expected_response_message_id = None;
                    self.sa.state = super::IkeSaState::IkeSaInitEstablished;
                    return Ok(());
                }
                SaInitOutcome::RetryWithCookie(cookie) => {
                    ensure!(attempt < 2, "peer requested too many COOKIE retries");
                    self.sa.sa_init_cookie = Some(cookie);
                }
                SaInitOutcome::RetryWithDhGroup(dh_group) => {
                    ensure!(attempt < 2, "peer requested too many INVALID_KE_PAYLOAD retries");
                    requested_dh_group = Some(dh_group);
                    self.sa.sa_init_cookie = None;
                }
            }
        }

        bail!("ike_sa_init did not complete after retry handling");
    }

    fn build_ike_sa_init_request(&mut self, dh_group: Option<u16>) -> Result<Bytes> {
        let local_selection = match dh_group {
            Some(dh_group) => self.first_ike_selection_for_dh_group(dh_group)?,
            None => self.first_ike_selection()?,
        };
        if self.sa.initiator_spi == 0 {
            self.sa.initiator_spi = Self::generate_spi();
        }
        if self.sa.initiator_nonce.is_none() {
            self.sa.initiator_nonce = Some(Bytes::from_owner(Self::generate_nonce()));
        }

        let local_keypair = (local_selection.dh.generate_keypair)().context("generate local KE")?;
        let public_key = (local_selection.dh.public_key)(&local_keypair).context("encode KE")?;
        self.local_dh = Some(local_keypair);
        self.sa.initiator_ke = Some(KeyExchangePayload {
            dh_group: local_selection.dh.transform_id,
            value: public_key,
        });
        self.selected_suite = Some(local_selection);
        self.build_ike_sa_init_packet()
    }

    fn build_ike_sa_init_packet(&mut self) -> Result<Bytes> {
        let natd = self.nat_detection_hashes(self.sa.initiator_spi, 0)?;
        let nonce = self.sa.initiator_nonce.clone().context("initiator nonce missing")?;

        let mut builder = IkeMessageBuilder::new(BytesMut::from(bytes_of(&IkeHeader::new(
            self.sa.initiator_spi,
            0,
            EXCHANGE_TYPE_IKE_SA_INIT,
            IkeFlags::INITIATOR,
            0,
        ))));
        if let Some(cookie) = self.sa.sa_init_cookie.clone() {
            builder.push_payload(PAYLOAD_TYPE_NOTIFY, false, |buf| {
                Self::append_notify_payload(buf, NOTIFY_TYPE_COOKIE, cookie.as_ref())
            });
        }
        builder.try_push_payload(PAYLOAD_TYPE_SA, false, |buf| {
            self.append_sa_proposals(buf, &self.config.ike_suite)
        })?;
        builder.try_push_payload(PAYLOAD_TYPE_KE, false, |buf| {
            self.append_ke_payload(
                buf,
                self.sa.initiator_ke.as_ref().context("initiator KE missing")?,
            );
            Ok(())
        })?;
        builder.push_payload(PAYLOAD_TYPE_NONCE, false, |buf| buf.extend_from_slice(&nonce));

        // notify
        macro_rules! append_notify {
            ($notify_type:expr, $data:expr) => {
                builder.push_payload(PAYLOAD_TYPE_NOTIFY, false, |out| {
                    out.extend_from_slice(bytes_of(&NotifyHeader {
                        protocol_id: 0,
                        spi_size: 0,
                        notify_type: $notify_type.into(),
                    }));
                    out.extend_from_slice($data);
                })
            };
        }
        append_notify!(NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP, natd.0.as_ref());
        append_notify!(NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP, natd.1.as_ref());
        append_notify!(NOTIFY_TYPE_FRAGMENTATION_SUPPORTED, &[]);
        append_notify!(
            NOTIFY_TYPE_SIGNATURE_HASH_ALGORITHMS,
            &Self::signature_hash_algorithms_notify()
        );

        let packet = Self::finalize_packet(builder)?;
        ensure!(packet.len() > IKE_HEADER_LEN, "failed to build outbound ike_sa_init");
        Ok(packet)
    }

    fn apply_sa_init_response(
        &mut self,
        header: crate::payload::IkeHeader,
        payloads: &[Payload],
    ) -> Result<SaInitOutcome> {
        let responder_spi =
            u64::from_be_bytes(bytemuck::bytes_of(&header.responder_spi).try_into().unwrap());
        let zero_spi_cookie_response = responder_spi == 0;
        let mut sa_selection = None;
        let mut responder_nonce = None;
        let mut responder_ke = None;
        let mut cookie = None;
        let mut invalid_ke = None;

        self.sa.nat.source_hash_remote = None;
        self.sa.nat.destination_hash_remote = None;
        self.sa.peer = PeerCapabilities::new();

        for payload in payloads {
            match payload.payload_type {
                PAYLOAD_TYPE_SA => {
                    sa_selection = Some(self.decode_sa_selection(payload.body.as_ref())?)
                }
                PAYLOAD_TYPE_NONCE => responder_nonce = Some(payload.body.clone()),
                PAYLOAD_TYPE_KE => {
                    responder_ke = Some(self.decode_ke_payload(payload.body.as_ref())?)
                }
                PAYLOAD_TYPE_NOTIFY => {
                    let notify = Self::decode_notify_payload(payload.body.as_ref())?;
                    let notify_type = notify.notify_type;
                    let notify_data = notify.data;
                    match notify_type {
                        NOTIFY_TYPE_COOKIE => {
                            ensure!(notify.spi.is_empty(), "COOKIE notify must not carry SPI");
                            ensure!(!notify_data.is_empty(), "COOKIE notify missing data");
                            cookie = Some(notify_data.to_vec().into_boxed_slice())
                        }
                        NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP => {
                            ensure!(
                                notify.protocol_id == 0 && notify.spi.is_empty(),
                                "NAT_DETECTION_SOURCE_IP must not carry SPI"
                            );
                            self.sa.nat.source_hash_remote =
                                Some(notify_data.to_vec().into_boxed_slice());
                        }
                        NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP => {
                            ensure!(
                                notify.protocol_id == 0 && notify.spi.is_empty(),
                                "NAT_DETECTION_DESTINATION_IP must not carry SPI"
                            );
                            self.sa.nat.destination_hash_remote =
                                Some(notify_data.to_vec().into_boxed_slice());
                        }
                        NOTIFY_TYPE_FRAGMENTATION_SUPPORTED => {
                            ensure!(
                                notify.protocol_id == 0 && notify.spi.is_empty(),
                                "FRAGMENTATION_SUPPORTED must not carry SPI"
                            );
                            self.sa.peer.supports_fragmentation = true;
                        }
                        NOTIFY_TYPE_SIGNATURE_HASH_ALGORITHMS => {
                            ensure!(
                                notify.protocol_id == 0 && notify.spi.is_empty(),
                                "SIGNATURE_HASH_ALGORITHMS must not carry SPI"
                            );
                            self.sa.auth.peer_signature_hash_algorithms =
                                Self::decode_signature_hash_algorithms_notify(notify_data)?;
                        }
                        NOTIFY_TYPE_INVALID_KE_PAYLOAD => {
                            ensure!(
                                notify.protocol_id == 0 && notify.spi.is_empty(),
                                "INVALID_KE_PAYLOAD must not carry SPI"
                            );
                            ensure!(
                                notify_data.len() == 2,
                                "INVALID_KE_PAYLOAD notify must carry one DH group"
                            );
                            invalid_ke = Some(u16::from_be_bytes([notify_data[0], notify_data[1]]));
                        }
                        NOTIFY_TYPE_NO_PROPOSAL_CHOSEN => {
                            bail!("peer rejected IKE proposal")
                        }
                        other if other < 16384 => {
                            bail!("received IKE_SA_INIT notify error {other}")
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        if zero_spi_cookie_response && cookie.is_some() {
            ensure!(sa_selection.is_none(), "zero-SPI COOKIE response must not include SA");
            ensure!(responder_ke.is_none(), "zero-SPI COOKIE response must not include KE");
            ensure!(responder_nonce.is_none(), "zero-SPI COOKIE response must not include NONCE");
        }

        if let Some(cookie) = cookie {
            ensure!(
                invalid_ke.is_none(),
                "COOKIE and INVALID_KE_PAYLOAD cannot both require retry"
            );
            return Ok(SaInitOutcome::RetryWithCookie(cookie));
        }
        if let Some(dh_group) = invalid_ke {
            ensure!(sa_selection.is_none(), "INVALID_KE_PAYLOAD response must not include SA");
            ensure!(responder_ke.is_none(), "INVALID_KE_PAYLOAD response must not include KE");
            ensure!(
                responder_nonce.is_none(),
                "INVALID_KE_PAYLOAD response must not include NONCE"
            );
            return Ok(SaInitOutcome::RetryWithDhGroup(dh_group));
        }

        let selected = sa_selection.context("ike_sa_init response missing SA payload")?;
        self.sa.sa_init_cookie = None;
        self.sa.responder_spi = responder_spi;
        self.sa.responder_nonce = Some(responder_nonce.context("ike_sa_init response missing Nr")?);
        self.sa.responder_ke = Some(responder_ke.context("ike_sa_init response missing KE")?);
        self.sa.nat.detected = self.nat_detected(self.sa.responder_spi)?;
        self.set_selected_ike_proposal(selected)?;
        Ok(SaInitOutcome::Established)
    }

    fn derive_ike_sa_keys(&mut self) -> Result<()> {
        let selection = self.selected_ike_proposal()?.clone();
        let local_dh = self.local_dh.take().context("missing local dh keypair")?;
        let responder_ke = self.sa.responder_ke.as_ref().context("missing responder ke")?;
        let responder_nonce =
            self.sa.responder_nonce.as_ref().context("missing responder nonce")?;
        let initiator_nonce =
            self.sa.initiator_nonce.as_ref().context("missing initiator nonce")?;
        let shared = (selection.dh.shared_secret)(local_dh, responder_ke.value.as_ref())
            .context("derive DH shared secret")?;
        let prf = selection.prf;
        let mut nonce_seed = Vec::with_capacity(initiator_nonce.len() + responder_nonce.len());
        nonce_seed.extend_from_slice(initiator_nonce);
        nonce_seed.extend_from_slice(responder_nonce);
        crate::debug_fmt::log_ike_bytes("nonce_i =>", initiator_nonce.as_ref());
        crate::debug_fmt::log_ike_bytes("nonce_r =>", responder_nonce.as_ref());
        crate::debug_fmt::log_ike_bytes("dh_shared_secret =>", shared.as_ref());
        crate::debug_fmt::log_ike_bytes("skeyseed_seed =>", nonce_seed.as_ref());
        let skeyseed =
            prf.gen_prf_vec(nonce_seed.as_ref(), shared.as_ref()).context("derive SKEYSEED")?;
        crate::debug_fmt::log_ike_bytes("skeyseed =>", skeyseed.as_ref());

        let mut seed = Vec::with_capacity(initiator_nonce.len() + responder_nonce.len() + 16);
        seed.extend_from_slice(initiator_nonce);
        seed.extend_from_slice(responder_nonce);
        seed.extend_from_slice(&self.sa.initiator_spi.to_be_bytes());
        seed.extend_from_slice(&self.sa.responder_spi.to_be_bytes());
        crate::debug_fmt::log_ike_bytes("prf+ seed =>", seed.as_ref());

        let integ_len = if selection.encryption.is_aead {
            0
        } else {
            selection.integrity.key_len_hint
        };
        let enc_len = selection.encryption.key_len;
        let prf_len = prf.output_len;
        let keymat = Self::prf_plus(
            prf,
            &skeyseed,
            seed.as_ref(),
            prf_len + integ_len * 2 + enc_len * 2 + prf_len * 2,
        )?;
        crate::debug_fmt::log_ike_bytes("ike keymat =>", keymat.as_ref());

        let mut offset = 0usize;
        let take = |src: &[u8], offset: &mut usize, len: usize| -> Box<[u8]> {
            let out = src[*offset..*offset + len].to_vec().into_boxed_slice();
            *offset += len;
            out
        };
        self.sa.key_material = Some(IkeKeyMaterial {
            sk_d: take(&keymat, &mut offset, prf_len),
            sk_ai: take(&keymat, &mut offset, integ_len),
            sk_ar: take(&keymat, &mut offset, integ_len),
            sk_ei: take(&keymat, &mut offset, enc_len),
            sk_er: take(&keymat, &mut offset, enc_len),
            sk_pi: take(&keymat, &mut offset, prf_len),
            sk_pr: take(&keymat, &mut offset, prf_len),
        });
        ensure!(self.sa.key_material.is_some(), "ike key derivation did not produce key material");
        Ok(())
    }
}

enum SaInitOutcome {
    Established,
    RetryWithCookie(Box<[u8]>),
    RetryWithDhGroup(u16),
}
