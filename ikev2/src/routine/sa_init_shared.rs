use anyhow::{Context, Result, anyhow, bail, ensure};
use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::IpAddr;
use std::collections::HashSet;

use super::{
    Ikev2Routine,
    common::{
        KeHeader, NotifyHeader, NotifyPayload, ParsedProposal, ProposalHeader, TransformHeader,
    },
};
use crate::{
    AssignedConfig, Ikev2EapHandshake, KeyExchangePayload,
    cipher::{DH_ALGS, ENCRYPTION_ALGS, INTEGRITY_ALGS, PRF_ALGS, Sha1, rand_bytes},
    config::{CipherSuite, CipherSuiteSelection},
    consts::{
        CFG_TYPE_REPLY, CONFIG_ATTR_INTERNAL_IP4_ADDRESS, CONFIG_ATTR_INTERNAL_IP4_DNS,
        CONFIG_ATTR_INTERNAL_IP6_ADDRESS, CONFIG_ATTR_INTERNAL_IP6_DNS, DELETE_PROTOCOL_ID_IKE,
        TRANSFORM_ATTR_FORMAT_TV_FLAG, TRANSFORM_ATTR_TYPE_KEY_LENGTH, TRANSFORM_TYPE_DH,
        TRANSFORM_TYPE_ENCR, TRANSFORM_TYPE_ESN, TRANSFORM_TYPE_INTEG, TRANSFORM_TYPE_LAST,
        TRANSFORM_TYPE_MORE, TRANSFORM_TYPE_PRF,
    },
    payload::{IKE_HEADER_LEN, IkeMessageBuilder, Payload, PayloadParseResult, PayloadParser},
};

const_variant!(
    u8:
    PROTOCOL_ID_IKE = 1u8;
    PROTOCOL_ID_AH = 2u8;
);

const_variant!(
    u16:
    HASH_ALGORITHM_SHA2_256 = 2u16;
    HASH_ALGORITHM_SHA2_384 = 3u16;
    HASH_ALGORITHM_SHA2_512 = 4u16;
);

const ESN_ID_NO_EXT_SEQ: u16 = 0;
const KE_PAYLOAD_FIXED_FIELDS_LEN: usize = 4;
const NOTIFY_PAYLOAD_FIXED_FIELDS_LEN: usize = 4;
const PROPOSAL_TYPE_LAST: u8 = 0;
const PROPOSAL_TYPE_MORE: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
struct ChildSaProposalHeader {
    // Last/More chaining, proposal length, proposal number, ESP protocol, SPI size, transform count.
    proposal: ProposalHeader,
    spi: rend::u32_be,
}

impl Ikev2Routine {
    pub(super) fn parse_response_plain(
        &mut self,
        packet: Bytes,
        exchange_type: u8,
        message_id: u32,
    ) -> Result<(crate::payload::IkeHeader, Vec<Payload>)> {
        self.validate_expected_response_message_id(message_id)?;
        let mut parser =
            PayloadParser::new(std::sync::Arc::new(self.empty_payload_context()), None);
        let parsed = parser.parse_packet(packet.clone())?;
        let PayloadParseResult::Done { header, payloads } = parsed else {
            bail!("unexpected fragmented unencrypted response");
        };
        crate::debug_fmt::log_ike_parsed("recv parsed", header, payloads.as_slice());
        self.validate_response_header(header, exchange_type, message_id)?;
        self.sa.last_completed_response_message_id = Some(message_id);
        self.sa.clear_outbound_request();
        Ok((header, payloads))
    }

    pub(super) fn selected_ike_proposal(&self) -> Result<&CipherSuiteSelection> {
        self.selected_suite.as_ref().ok_or_else(|| anyhow!("ike proposal missing"))
    }

    pub(super) fn first_ike_suite(&self) -> Result<&CipherSuite> {
        self.config.ike_suite.first().ok_or_else(|| anyhow!("ike_suite is required"))
    }

    pub(super) fn first_ike_selection(&self) -> Result<CipherSuiteSelection> {
        let suite = self.first_ike_suite()?;
        suite.select(suite)
    }

    pub(crate) fn selected_esp_proposal(&self) -> Result<&CipherSuiteSelection> {
        self.selected_child_suite
            .as_ref()
            .ok_or_else(|| anyhow!("child proposal missing"))
    }

    fn child_sa_offer_variants(&self) -> Result<Vec<(CipherSuite, bool)>> {
        ensure!(!self.config.esp_suite.is_empty(), "esp_suite is required");
        let mut offers = Vec::new();
        let mut seen = HashSet::new();
        for suite in &self.config.esp_suite {
            let key = (suite.encryption.clone(), suite.integrity.clone(), false);
            if seen.insert(key) {
                offers.push((suite.clone(), false));
            }
            let has_aead = suite
                .encryption
                .iter()
                .filter_map(|alg| ENCRYPTION_ALGS.get(alg))
                .any(|alg| alg.is_aead);
            if self.config.strongswan_compatible && has_aead {
                let compat_key = (suite.encryption.clone(), suite.integrity.clone(), true);
                if seen.insert(compat_key) {
                    offers.push((suite.clone(), true));
                }
            }
        }
        Ok(offers)
    }

    pub(super) fn first_ike_selection_for_dh_group(
        &self,
        dh_group: u16,
    ) -> Result<CipherSuiteSelection> {
        let suite = self
            .config
            .ike_suite
            .iter()
            .find(|suite| suite.dh.contains(&dh_group))
            .with_context(|| format!("peer requested unsupported DH group {dh_group}"))?;
        suite.select(suite)
    }

    fn empty_payload_context(&self) -> Ikev2EapHandshake {
        Ikev2EapHandshake::new(Default::default())
    }

    pub(super) fn set_selected_ike_proposal(
        &mut self,
        selected: CipherSuiteSelection,
    ) -> Result<()> {
        let remote = CipherSuite {
            encryption: vec![(
                selected.encryption.transform_id,
                selected.encryption.transform_key_len as u16,
            )],
            integrity: if selected.encryption.is_aead {
                Vec::new()
            } else {
                vec![selected.integrity.transform_id]
            },
            prf: vec![selected.prf.transform_id],
            dh: vec![selected.dh.transform_id],
        };
        let local = self
            .config
            .ike_suite
            .iter()
            .find_map(|suite| suite.select(&remote).ok())
            .context("peer selected unsupported IKE proposal")?;
        self.selected_suite = Some(local);
        Ok(())
    }

    pub(super) fn append_sa_proposals(
        &self,
        out: &mut BytesMut,
        suites: &[CipherSuite],
    ) -> Result<()> {
        ensure!(!suites.is_empty(), "cipher suite list is empty");
        for (index, suite) in suites.iter().enumerate() {
            let mut transforms = BytesMut::new();
            let mut transform_count = 0u8;
            let has_aead = suite
                .encryption
                .iter()
                .filter_map(|alg| ENCRYPTION_ALGS.get(alg))
                .any(|alg| alg.is_aead);
            for encryption in &suite.encryption {
                let encryption = ENCRYPTION_ALGS
                    .get(encryption)
                    .with_context(|| format!("unsupported IKE encryption {:?}", encryption))?;
                self.append_transform(
                    &mut transforms,
                    TRANSFORM_TYPE_ENCR,
                    encryption.transform_id,
                    &Self::encode_key_length_attr(Self::key_len_bytes_to_bits(
                        encryption.transform_key_len,
                    )?),
                    false,
                );
                transform_count = transform_count.saturating_add(1);
            }
            for prf in &suite.prf {
                let prf = PRF_ALGS.get(prf).with_context(|| format!("unsupported IKE PRF {:?}", prf))?;
                self.append_transform(&mut transforms, TRANSFORM_TYPE_PRF, prf.transform_id, &[], false);
                transform_count = transform_count.saturating_add(1);
            }
            if !has_aead {
                for integrity in &suite.integrity {
                    let integrity = INTEGRITY_ALGS
                        .get(integrity)
                        .with_context(|| format!("unsupported IKE integrity {:?}", integrity))?;
                    self.append_transform(
                        &mut transforms,
                        TRANSFORM_TYPE_INTEG,
                        integrity.transform_id,
                        &[],
                        false,
                    );
                    transform_count = transform_count.saturating_add(1);
                }
            }
            for (dh_index, dh) in suite.dh.iter().enumerate() {
                let dh = DH_ALGS.get(dh).with_context(|| format!("unsupported IKE DH {:?}", dh))?;
                self.append_transform(
                    &mut transforms,
                    TRANSFORM_TYPE_DH,
                    dh.transform_id,
                    &[],
                    dh_index + 1 == suite.dh.len(),
                );
                transform_count = transform_count.saturating_add(1);
            }
            out.extend_from_slice(bytes_of(&ProposalHeader {
                last_substructure: if index + 1 == suites.len() { 0 } else { 2 },
                reserved: 0,
                proposal_length: ((std::mem::size_of::<ProposalHeader>() + transforms.len())
                    as u16)
                    .into(),
                proposal_num: (index + 1) as u8,
                protocol_id: 1,
                spi_size: 0,
                num_transforms: transform_count,
            }));
            out.extend_from_slice(&transforms);
        }
        Ok(())
    }

    pub(super) fn append_child_sa_proposals(
        &self,
        payload: &mut BytesMut,
        suites: &[CipherSuite],
        spi: u32,
    ) -> Result<()> {
        let offers = self.child_sa_offer_variants()?;
        ensure!(!offers.is_empty(), "esp_suite is required");
        ensure!(!suites.is_empty(), "esp_suite is required");
        for (index, (suite, omit_esn)) in offers.iter().enumerate() {
            let mut transforms = BytesMut::new();
            let has_aead = suite
                .encryption
                .iter()
                .filter_map(|alg| ENCRYPTION_ALGS.get(alg))
                .any(|alg| alg.is_aead);
            let mut transform_count = 0u8;
            for (enc_index, encryption) in suite.encryption.iter().enumerate() {
                let encryption = ENCRYPTION_ALGS
                    .get(encryption)
                    .with_context(|| format!("unsupported CHILD_SA encryption {:?}", encryption))?;
                let last_encr = enc_index + 1 == suite.encryption.len();
                self.append_transform(
                    &mut transforms,
                    TRANSFORM_TYPE_ENCR,
                    encryption.transform_id,
                    &Self::encode_key_length_attr(Self::key_len_bytes_to_bits(
                        encryption.transform_key_len,
                    )?),
                    has_aead && *omit_esn && last_encr,
                );
                transform_count = transform_count.saturating_add(1);
            }
            if !has_aead {
                for integrity in &suite.integrity {
                    let integrity = INTEGRITY_ALGS
                        .get(integrity)
                        .with_context(|| format!("unsupported CHILD_SA integrity {:?}", integrity))?;
                    self.append_transform(
                        &mut transforms,
                        TRANSFORM_TYPE_INTEG,
                        integrity.transform_id,
                        &[],
                        false,
                    );
                    transform_count = transform_count.saturating_add(1);
                }
            }
            if !*omit_esn {
                self.append_transform(
                    &mut transforms,
                    TRANSFORM_TYPE_ESN,
                    ESN_ID_NO_EXT_SEQ,
                    &[],
                    true,
                );
                transform_count = transform_count.saturating_add(1);
            }
            payload.extend_from_slice(bytes_of(&ChildSaProposalHeader {
                proposal: ProposalHeader {
                    last_substructure: if index + 1 == offers.len() {
                        PROPOSAL_TYPE_LAST
                    } else {
                        PROPOSAL_TYPE_MORE
                    },
                    reserved: 0,
                    proposal_length: ((std::mem::size_of::<ChildSaProposalHeader>()
                        + transforms.len()) as u16)
                        .into(),
                    proposal_num: (index + 1) as u8,
                    protocol_id: 3,
                    spi_size: 4,
                    num_transforms: transform_count,
                },
                spi: spi.into(),
            }));
            payload.extend_from_slice(&transforms);
        }
        Ok(())
    }

    fn append_transform(
        &self,
        out: &mut BytesMut,
        transform_type: u8,
        transform_id: u16,
        attrs: &[u8],
        last: bool,
    ) {
        out.extend_from_slice(bytes_of(&TransformHeader {
            last_substructure: if last { TRANSFORM_TYPE_LAST } else { TRANSFORM_TYPE_MORE },
            reserved: 0,
            transform_length: ((std::mem::size_of::<TransformHeader>() + attrs.len()) as u16)
                .into(),
            transform_type,
            transform_reserved: 0,
            transform_id: transform_id.into(),
        }));
        out.extend_from_slice(attrs);
    }

    fn encode_key_length_attr(bits: u16) -> [u8; 4] {
        let attr = (TRANSFORM_ATTR_FORMAT_TV_FLAG | TRANSFORM_ATTR_TYPE_KEY_LENGTH).to_be_bytes();
        let bits = bits.to_be_bytes();
        [attr[0], attr[1], bits[0], bits[1]]
    }

    fn key_len_bytes_to_bits(bytes: usize) -> Result<u16> {
        let bytes = u16::try_from(bytes).context("encryption key length too large")?;
        bytes.checked_mul(8).context("encryption key length too large")
    }

    fn key_len_bits_to_bytes(bits: u16) -> Result<u16> {
        ensure!(bits != 0 && bits.is_multiple_of(8), "invalid encryption key length");
        Ok(bits / 8)
    }

    pub(super) fn append_ke_payload(&self, out: &mut BytesMut, ke: &KeyExchangePayload) {
        out.extend_from_slice(bytes_of(&KeHeader {
            dh_group: ke.dh_group.into(),
            reserved: 0.into(),
        }));
        out.extend_from_slice(ke.value.as_ref());
    }

    pub(super) fn decode_ke_payload(&self, payload: &[u8]) -> Result<KeyExchangePayload> {
        ensure!(payload.len() >= KE_PAYLOAD_FIXED_FIELDS_LEN, "invalid KE payload");
        let header = pod_read_unaligned::<KeHeader>(&payload[..KE_PAYLOAD_FIXED_FIELDS_LEN]);
        let value = payload[KE_PAYLOAD_FIXED_FIELDS_LEN..].to_vec().into_boxed_slice();
        ensure!(!value.is_empty(), "invalid KE payload: empty key data");
        Ok(KeyExchangePayload { dh_group: header.dh_group.to_native(), value })
    }

    pub(super) fn decode_sa_selection(&self, payload: &[u8]) -> Result<CipherSuiteSelection> {
        let proposal = Self::parse_single_proposal(payload, PROTOCOL_ID_IKE, 0)?;
        let encryption = proposal.encryption.context("missing encryption transform")?;
        if encryption.is_aead {
            ensure!(proposal.integrity.is_none(), "unexpected integrity transform for AEAD IKE proposal");
        }
        let integrity = if encryption.is_aead {
            &crate::cipher::AUTH_NONE_ALG
        } else {
            proposal.integrity.context("missing integrity transform")?
        };
        let prf = proposal.prf.context("missing PRF transform")?;
        let dh = proposal.dh.context("missing DH transform")?;
        ensure!(proposal.esn.is_none(), "unexpected ESN transform in IKE proposal");
        let proposal_index = usize::from(proposal.proposal_num)
            .checked_sub(1)
            .context("peer returned invalid IKE proposal number")?;
        let suite = self
            .config
            .ike_suite
            .get(proposal_index)
            .context("peer selected an unoffered IKE proposal number")?;
        let remote = CipherSuite {
            encryption: vec![(
                encryption.transform_id,
                encryption.transform_key_len as u16,
            )],
            integrity: if encryption.is_aead {
                Vec::new()
            } else {
                vec![integrity.transform_id]
            },
            prf: vec![prf.transform_id],
            dh: vec![dh.transform_id],
        };
        let selection = suite.select(&remote)?;
        ensure!(
            Self::selection_matches_ike_transforms(
                &selection,
                encryption.transform_id,
                Self::key_len_bytes_to_bits(encryption.transform_key_len)?,
                if encryption.is_aead { None } else { Some(integrity.transform_id) },
                prf.transform_id,
                dh.transform_id,
            ),
            "peer selected transforms that do not match the offered IKE proposal"
        );
        Ok(selection)
    }

    pub(super) fn decode_child_sa_selection(
        &self,
        payload: &[u8],
    ) -> Result<(u32, CipherSuiteSelection)> {
        let proposal = Self::parse_single_proposal(payload, super::common::PROTOCOL_ID_ESP, 4)?;
        let spi = proposal.spi.context("missing CHILD_SA SPI")?;
        let encryption = proposal.encryption.context("missing CHILD_SA encryption transform")?;
        if encryption.is_aead {
            ensure!(
                proposal.integrity.is_none(),
                "unexpected integrity transform for AEAD CHILD_SA proposal"
            );
        }
        let integrity = if encryption.is_aead {
            &crate::cipher::AUTH_NONE_ALG
        } else {
            proposal.integrity.context("missing CHILD_SA integrity transform")?
        };
        ensure!(proposal.prf.is_none(), "unexpected PRF transform in CHILD_SA proposal");
        ensure!(proposal.dh.is_none(), "unexpected DH transform in CHILD_SA proposal");
        let esn = proposal.esn.unwrap_or(ESN_ID_NO_EXT_SEQ);
        ensure!(esn == ESN_ID_NO_EXT_SEQ, "unsupported CHILD_SA ESN mode");
        let offers = self.child_sa_offer_variants()?;
        let (suite, _) = offers
            .get(usize::from(proposal.proposal_num).checked_sub(1).context("peer returned invalid CHILD_SA proposal number")?)
            .context("peer selected an unoffered CHILD_SA proposal number")?;
        let selection = CipherSuiteSelection {
            encryption: suite
                .encryption
                .iter()
                .find(|candidate| **candidate == (
                    encryption.transform_id,
                    encryption.transform_key_len as u16,
                ))
                .and_then(|candidate| ENCRYPTION_ALGS.get(candidate))
                .context("peer selected unsupported CHILD_SA encryption transform")?,
            integrity: if encryption.is_aead {
                &crate::cipher::AUTH_NONE_ALG
            } else {
                suite
                    .integrity
                    .iter()
                    .find(|candidate| **candidate == integrity.transform_id)
                    .and_then(|candidate| INTEGRITY_ALGS.get(candidate))
                    .context("peer selected unsupported CHILD_SA integrity transform")?
            },
            prf: self.selected_ike_proposal()?.prf,
            dh: self.selected_ike_proposal()?.dh,
        };
        ensure!(
            Self::selection_matches_child_transforms(
                &selection,
                encryption.transform_id,
                Self::key_len_bytes_to_bits(encryption.transform_key_len)?,
                if encryption.is_aead { None } else { Some(integrity.transform_id) },
            ),
            "peer selected transforms that do not match the offered CHILD_SA proposal"
        );
        Ok((spi, selection))
    }

    fn parse_single_proposal(
        payload: &[u8],
        protocol_id: u8,
        spi_size: u8,
    ) -> Result<ParsedProposal> {
        ensure!(payload.len() >= std::mem::size_of::<ProposalHeader>(), "invalid SA payload");
        let header =
            pod_read_unaligned::<ProposalHeader>(&payload[..std::mem::size_of::<ProposalHeader>()]);
        let expected_transforms = header.num_transforms;
        let proposal_len = header.proposal_length.to_native() as usize;
        let header_len = std::mem::size_of::<ProposalHeader>();
        ensure!(proposal_len >= header_len + usize::from(spi_size), "invalid SA proposal length");
        ensure!(proposal_len == payload.len(), "unexpected SA proposal length");
        ensure!(header.proposal_num != 0, "unexpected proposal number");
        ensure!(header.protocol_id == protocol_id, "unexpected proposal protocol");
        ensure!(header.spi_size == spi_size, "unexpected proposal SPI size");
        ensure!(expected_transforms != 0, "proposal missing transforms");
        ensure!(header.last_substructure == 0, "unexpected extra SA proposal");

        let spi_start = header_len;
        let spi_end = spi_start + header.spi_size as usize;
        ensure!(spi_end <= payload.len(), "proposal SPI out of bounds");
        let spi = match spi_size {
            0 => None,
            4 => Some(u32::from_be_bytes(payload[spi_start..spi_end].try_into().unwrap())),
            _ => bail!("unsupported proposal SPI size {spi_size}"),
        };

        let mut parsed = ParsedProposal {
            proposal_num: header.proposal_num,
            spi,
            encryption: None,
            integrity: None,
            prf: None,
            dh: None,
            esn: None,
        };
        let mut offset = spi_end;
        let mut transforms = 0u8;
        while offset + std::mem::size_of::<TransformHeader>() <= payload.len() {
            let header = pod_read_unaligned::<TransformHeader>(
                &payload[offset..offset + std::mem::size_of::<TransformHeader>()],
            );
            let transform_len = header.transform_length.to_native() as usize;
            ensure!(
                transform_len >= std::mem::size_of::<TransformHeader>()
                    && offset + transform_len <= payload.len(),
                "invalid SA transform"
            );
            let attrs =
                &payload[offset + std::mem::size_of::<TransformHeader>()..offset + transform_len];
            let transform_id = header.transform_id.to_native();
            match header.transform_type {
                TRANSFORM_TYPE_ENCR => {
                    ensure!(parsed.encryption.is_none(), "multiple encryption transforms selected");
                    parsed.encryption =
                        Some(Self::decode_encryption_transform(transform_id, attrs)?);
                }
                TRANSFORM_TYPE_INTEG => {
                    ensure!(parsed.integrity.is_none(), "multiple integrity transforms selected");
                    parsed.integrity = Some(
                        INTEGRITY_ALGS
                            .get(&transform_id)
                            .context("unsupported integrity transform")?,
                    );
                    ensure!(attrs.is_empty(), "unexpected integrity attributes");
                }
                TRANSFORM_TYPE_PRF => {
                    ensure!(parsed.prf.is_none(), "multiple PRF transforms selected");
                    parsed.prf =
                        Some(PRF_ALGS.get(&transform_id).context("unsupported PRF transform")?);
                    ensure!(attrs.is_empty(), "unexpected PRF attributes");
                }
                TRANSFORM_TYPE_DH => {
                    ensure!(parsed.dh.is_none(), "multiple DH transforms selected");
                    parsed.dh =
                        Some(DH_ALGS.get(&transform_id).context("unsupported DH transform")?);
                    ensure!(attrs.is_empty(), "unexpected DH attributes");
                }
                TRANSFORM_TYPE_ESN => {
                    ensure!(parsed.esn.is_none(), "multiple ESN transforms selected");
                    ensure!(attrs.is_empty(), "unexpected ESN attributes");
                    parsed.esn = Some(transform_id);
                }
                _ => bail!("unsupported transform type {}", header.transform_type),
            }
            transforms = transforms.saturating_add(1);
            offset += transform_len;
            if header.last_substructure == TRANSFORM_TYPE_LAST {
                break;
            }
            ensure!(
                header.last_substructure == TRANSFORM_TYPE_MORE,
                "invalid transform chaining flag"
            );
        }
        ensure!(offset == payload.len(), "unexpected trailing proposal bytes");
        ensure!(transforms == expected_transforms, "proposal transform count mismatch");
        Ok(parsed)
    }

    fn decode_encryption_transform(
        transform_id: u16,
        attrs: &[u8],
    ) -> Result<&'static crate::cipher::EncryptionAlg> {
        let bits = Self::decode_key_length_attr(attrs)?;
        let bytes = Self::key_len_bits_to_bytes(bits)?;
        ENCRYPTION_ALGS.get(&(transform_id, bytes)).context("unsupported encryption selection")
    }

    fn decode_key_length_attr(attrs: &[u8]) -> Result<u16> {
        ensure!(attrs.len() == 4, "invalid encryption attributes");
        let ty = u16::from_be_bytes([attrs[0], attrs[1]]);
        ensure!(
            (ty & !TRANSFORM_ATTR_FORMAT_TV_FLAG) == TRANSFORM_ATTR_TYPE_KEY_LENGTH,
            "unsupported encryption attribute"
        );
        ensure!((ty & TRANSFORM_ATTR_FORMAT_TV_FLAG) != 0, "KEY_LENGTH must use TV format");
        Ok(u16::from_be_bytes([attrs[2], attrs[3]]))
    }

    fn selection_matches_ike_transforms(
        selection: &CipherSuiteSelection,
        encryption_transform_id: u16,
        encryption_key_len_bits: u16,
        integrity_transform_id: Option<u16>,
        prf_transform_id: u16,
        dh_transform_id: u16,
    ) -> bool {
        selection.encryption.transform_id == encryption_transform_id
            && Self::key_len_bytes_to_bits(selection.encryption.transform_key_len)
                .ok()
                .is_some_and(|bits| bits == encryption_key_len_bits)
            && (selection.encryption.is_aead
                || integrity_transform_id
                    .is_some_and(|transform_id| selection.integrity.transform_id == transform_id))
            && selection.prf.transform_id == prf_transform_id
            && selection.dh.transform_id == dh_transform_id
    }

    fn selection_matches_child_transforms(
        selection: &CipherSuiteSelection,
        encryption_transform_id: u16,
        encryption_key_len_bits: u16,
        integrity_transform_id: Option<u16>,
    ) -> bool {
        selection.encryption.transform_id == encryption_transform_id
            && Self::key_len_bytes_to_bits(selection.encryption.transform_key_len)
                .ok()
                .is_some_and(|bits| bits == encryption_key_len_bits)
            && (selection.encryption.is_aead
                || integrity_transform_id
                    .is_some_and(|transform_id| selection.integrity.transform_id == transform_id))
    }

    pub(super) fn decode_assigned_config(&self, cp_payload: &[u8]) -> Result<AssignedConfig> {
        ensure!(cp_payload.len() >= 4, "invalid CP payload");
        ensure!(cp_payload[0] == CFG_TYPE_REPLY, "unexpected CP payload type in IKE_AUTH response");
        let mut assigned = AssignedConfig::default();
        let mut offset = 4usize;
        while offset < cp_payload.len() {
            ensure!(offset + 4 <= cp_payload.len(), "invalid CP attribute header");
            let attr_type = u16::from_be_bytes([cp_payload[offset], cp_payload[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([cp_payload[offset + 2], cp_payload[offset + 3]]) as usize;
            offset += 4;
            ensure!(offset + attr_len <= cp_payload.len(), "invalid CP attribute value");
            let value = &cp_payload[offset..offset + attr_len];
            match attr_type {
                CONFIG_ATTR_INTERNAL_IP4_ADDRESS => {
                    if !value.is_empty() {
                        ensure!(value.len() == 4, "invalid INTERNAL_IP4_ADDRESS length");
                        assigned.internal_ipv4 = Some([value[0], value[1], value[2], value[3]]);
                    }
                }
                CONFIG_ATTR_INTERNAL_IP4_DNS => {
                    ensure!(value.len() == 4, "invalid INTERNAL_IP4_DNS length");
                    assigned.dns4.push([value[0], value[1], value[2], value[3]]);
                }
                CONFIG_ATTR_INTERNAL_IP6_ADDRESS => {
                    if !value.is_empty() {
                        ensure!(value.len() == 17, "invalid INTERNAL_IP6_ADDRESS length");
                        let prefix_len = value[16];
                        ensure!(prefix_len <= 128, "invalid INTERNAL_IP6_ADDRESS prefix length");
                        assigned.internal_ipv6 = Some(
                            <[u8; 16]>::try_from(&value[..16])
                                .context("invalid INTERNAL_IP6_ADDRESS")?,
                        );
                        assigned.internal_ipv6_prefix_len = Some(prefix_len);
                    }
                }
                CONFIG_ATTR_INTERNAL_IP6_DNS => {
                    ensure!(value.len() == 16, "invalid INTERNAL_IP6_DNS length");
                    assigned
                        .dns6
                        .push(<[u8; 16]>::try_from(value).context("invalid INTERNAL_IP6_DNS")?);
                }
                _ => {}
            }
            offset += attr_len;
        }
        Ok(assigned)
    }

    pub(super) fn finalize_packet(mut builder: IkeMessageBuilder) -> Result<Bytes> {
        ensure!(builder.buffer.len() >= IKE_HEADER_LEN, "ike packet too short");
        builder.buffer[16] = builder.first_payload;
        let len = builder.buffer.len() as u32;
        builder.buffer[24..28].copy_from_slice(&len.to_be_bytes());
        Ok(builder.buffer.freeze())
    }

    pub(super) fn append_notify_payload(out: &mut BytesMut, notify_type: u16, data: &[u8]) {
        out.extend_from_slice(bytes_of(&NotifyHeader {
            protocol_id: 0,
            spi_size: 0,
            notify_type: notify_type.into(),
        }));
        out.extend_from_slice(data);
    }

    pub(super) fn encode_delete_payload(protocol_id: u8, spis: &[u32]) -> Bytes {
        let spi_size = if spis.is_empty() { 0 } else { 4 };
        let mut payload = Vec::with_capacity(4 + spis.len() * 4);
        payload.push(protocol_id);
        payload.push(spi_size);
        payload.extend_from_slice(&(spis.len() as u16).to_be_bytes());
        for spi in spis {
            payload.extend_from_slice(&spi.to_be_bytes());
        }
        Bytes::from(payload)
    }

    pub(super) const fn signature_hash_algorithms_notify() -> [u8; 6] {
        SUPPORTED_SIGNATURE_HASH_ALGORITHMS_PAYLOAD
    }

    pub(super) fn decode_notify_payload(payload: &[u8]) -> Result<NotifyPayload<'_>> {
        ensure!(payload.len() >= NOTIFY_PAYLOAD_FIXED_FIELDS_LEN, "invalid NOTIFY payload");
        let header =
            pod_read_unaligned::<NotifyHeader>(&payload[..NOTIFY_PAYLOAD_FIXED_FIELDS_LEN]);
        ensure!(
            matches!(
                header.protocol_id,
                0 | PROTOCOL_ID_IKE | PROTOCOL_ID_AH | super::common::PROTOCOL_ID_ESP
            ),
            "unsupported NOTIFY protocol"
        );
        let spi_start = NOTIFY_PAYLOAD_FIXED_FIELDS_LEN;
        let spi_end = spi_start + header.spi_size as usize;
        ensure!(spi_end <= payload.len(), "invalid NOTIFY SPI length");
        if header.spi_size == 0 {
            ensure!(
                header.protocol_id == 0 || header.protocol_id == DELETE_PROTOCOL_ID_IKE,
                "NOTIFY without SPI must use protocol 0 or IKE"
            );
        } else {
            ensure!(
                matches!(header.protocol_id, PROTOCOL_ID_AH | super::common::PROTOCOL_ID_ESP),
                "NOTIFY with SPI must target AH or ESP"
            );
        }
        Ok(NotifyPayload {
            protocol_id: header.protocol_id,
            spi: &payload[spi_start..spi_end],
            notify_type: header.notify_type.to_native(),
            data: &payload[spi_end..],
        })
    }

    pub(super) fn decode_signature_hash_algorithms_notify(data: &[u8]) -> Result<Box<[u16]>> {
        ensure!(
            !data.is_empty() && data.len().is_multiple_of(2),
            "invalid SIGNATURE_HASH_ALGORITHMS notify data"
        );
        let mut algorithms = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks_exact(2) {
            algorithms.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Ok(algorithms.into_boxed_slice())
    }

    pub(super) fn nat_detection_hashes(
        &self,
        initiator_spi: u64,
        responder_spi: u64,
    ) -> Result<(Bytes, Bytes)> {
        let transport = self.transport.as_ref().context("missing transport setup for NAT-D")?;
        let local = transport.local_addr;
        let peer = transport.peer_addr;
        Ok((
            Self::nat_detection_hash(
                initiator_spi,
                responder_spi,
                local.ip(),
                crate::IKEV2_NAT_T_PORT,
            )?,
            Self::nat_detection_hash(
                initiator_spi,
                responder_spi,
                peer.ip(),
                crate::IKEV2_NAT_T_PORT,
            )?,
        ))
    }

    fn nat_detection_hash(
        initiator_spi: u64,
        responder_spi: u64,
        addr: IpAddr,
        port: u16,
    ) -> Result<Bytes> {
        let mut seed = Vec::with_capacity(8 + 8 + 16 + 2);
        seed.extend_from_slice(&initiator_spi.to_be_bytes());
        seed.extend_from_slice(&responder_spi.to_be_bytes());
        match addr {
            IpAddr::V4(addr) => seed.extend_from_slice(&addr.octets()),
            IpAddr::V6(addr) => seed.extend_from_slice(&addr.octets()),
        }
        seed.extend_from_slice(&port.to_be_bytes());
        crate::debug_fmt::log_ike_bytes("natd_chunk =>", seed.as_ref());
        let digest = Sha1::digest(&seed);
        crate::debug_fmt::log_ike_bytes("natd_hash =>", &digest);
        Ok(Bytes::copy_from_slice(&digest))
    }

    pub(super) fn nat_detected(&self, responder_spi: u64) -> Result<bool> {
        let local = self.nat_detection_hashes(self.sa.initiator_spi, responder_spi)?;
        crate::debug_fmt::log_ike_bytes("precalculated src_hash =>", local.0.as_ref());
        crate::debug_fmt::log_ike_bytes("precalculated dst_hash =>", local.1.as_ref());
        if let Some(remote) = self.sa.nat.source_hash_remote.as_deref() {
            crate::debug_fmt::log_ike_bytes("received src_hash =>", remote);
        }
        if let Some(remote) = self.sa.nat.destination_hash_remote.as_deref() {
            crate::debug_fmt::log_ike_bytes("received dst_hash =>", remote);
        }
        Ok(self.sa.nat.source_hash_remote.as_deref().is_some_and(|v| v != local.0.as_ref())
            || self
                .sa
                .nat
                .destination_hash_remote
                .as_deref()
                .is_some_and(|v| v != local.1.as_ref()))
    }

    pub(super) fn prf_plus(
        prf: &crate::cipher::PrfAlg,
        key: &[u8],
        seed: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(out_len);
        let mut previous = Vec::new();
        let mut counter = 1u8;
        while out.len() < out_len {
            let mut block = Vec::with_capacity(previous.len() + seed.len() + 1);
            if !previous.is_empty() {
                block.extend_from_slice(&previous);
            }
            block.extend_from_slice(seed);
            block.put_u8(counter);
            previous.resize(prf.output_len, 0);
            (prf.gen_prf)(key, block.as_ref(), &mut previous)?;
            out.extend_from_slice(&previous);
            counter = counter.saturating_add(1);
        }
        out.truncate(out_len);
        Ok(out)
    }

    pub(super) fn generate_spi() -> u64 {
        let mut bytes = [0u8; 8];
        rand_bytes(&mut bytes);
        u64::from_be_bytes(bytes).max(1)
    }

    pub(super) fn generate_nonce() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand_bytes(&mut bytes);
        bytes
    }
}

const fn supported_signature_hash_algorithms_payload<const L: usize, const L2: usize>(
    i: [u16; L],
) -> [u8; L2] {
    let mut o = [0u8; L2];
    let mut k = 0;
    while k < i.len() {
        [o[2 * k], o[2 * k + 1]] = i[k].to_be_bytes();
        k += 1;
    }
    o
}

const SUPPORTED_SIGNATURE_HASH_ALGORITHMS: [u16; 3] =
    [HASH_ALGORITHM_SHA2_256, HASH_ALGORITHM_SHA2_384, HASH_ALGORITHM_SHA2_512];
const SUPPORTED_SIGNATURE_HASH_ALGORITHMS_PAYLOAD: [u8; 6] =
    supported_signature_hash_algorithms_payload(SUPPORTED_SIGNATURE_HASH_ALGORITHMS);
