type NameInfo = (&'static str, &'static str);

const_variant! {
    EXCHANGE_TYPE_NAMES, u8, NameInfo:
    (EXCHANGE_TYPE_IKE_SA_INIT, 34u8, ("IKE_SA_INIT", "IKE SA Init")),
    (EXCHANGE_TYPE_IKE_AUTH, 35u8, ("IKE_AUTH", "IKE Authentication")),
    (EXCHANGE_TYPE_CREATE_CHILD_SA, 36u8, ("CREATE_CHILD_SA", "Create Child SA")),
    (EXCHANGE_TYPE_INFORMATIONAL, 37u8, ("INFORMATIONAL", "Informational")),
}

const_variant! {
    ID_TYPE_NAMES, u8, NameInfo:
    (ID_TYPE_IPV4_ADDR, 1u8, ("IPV4_ADDR", "IPv4 Address")),
    (ID_TYPE_FQDN, 2u8, ("FQDN", "Fully Qualified Domain Name")),
    (ID_TYPE_RFC822_ADDR, 3u8, ("RFC822_ADDR", "RFC 822 Address")),
    (ID_TYPE_IPV6_ADDR, 5u8, ("IPV6_ADDR", "IPv6 Address")),
    (ID_TYPE_DER_ASN1_DN, 9u8, ("DER_ASN1_DN", "DER ASN.1 Distinguished Name")),
    (ID_TYPE_KEY_ID, 11u8, ("KEY_ID", "Key Identifier")),
}

const_variant! {
    DELETE_PROTOCOL_ID_NAMES, u8, &'static str:
    (DELETE_PROTOCOL_ID_IKE, 1u8, "IKE"),
    (DELETE_PROTOCOL_ID_ESP, 3u8, "ESP"),
}

const_variant! {
    TRANSFORM_TYPE_NAMES, u8, NameInfo:
    (TRANSFORM_TYPE_ENCR, 1u8, ("ENCR", "Encryption Algorithm")),
    (TRANSFORM_TYPE_PRF, 2u8, ("PRF", "Pseudorandom Function")),
    (TRANSFORM_TYPE_INTEG, 3u8, ("INTEG", "Integrity Algorithm")),
    (TRANSFORM_TYPE_DH, 4u8, ("DH", "Diffie-Hellman Group")),
    (TRANSFORM_TYPE_ESN, 5u8, ("ESN", "Extended Sequence Numbers")),
}

pub const TRANSFORM_TYPE_LAST: u8 = 0;
pub const TRANSFORM_TYPE_MORE: u8 = 3;
pub const TRANSFORM_ATTR_TYPE_KEY_LENGTH: u16 = 14;
pub const TRANSFORM_ATTR_FORMAT_TV_FLAG: u16 = 0x8000;

const_variant! {
    NOTIFY_TYPE_NAMES, u16, NameInfo:
    (NOTIFY_TYPE_NO_PROPOSAL_CHOSEN, 14u16, ("NO_PROP", "No Proposal Chosen")),
    (NOTIFY_TYPE_INVALID_KE_PAYLOAD, 17u16, ("INVAL_KE", "Invalid KE Payload")),
    (NOTIFY_TYPE_AUTHENTICATION_FAILED, 24u16, ("AUTH_FAILED", "Authentication Failed")),
    (NOTIFY_TYPE_SINGLE_PAIR_REQUIRED, 34u16, ("SINGLE_PAIR", "Single Pair Required")),
    (NOTIFY_TYPE_NO_ADDITIONAL_SAS, 35u16, ("NO_ADD_SA", "No Additional SAs")),
    (NOTIFY_TYPE_INTERNAL_ADDRESS_FAILURE, 36u16, ("ADDR_FAIL", "Internal Address Failure")),
    (NOTIFY_TYPE_FAILED_CP_REQUIRED, 37u16, ("FAILED_CP_REQUIRED", "Failed CP Required")),
    (NOTIFY_TYPE_TS_UNACCEPTABLE, 38u16, ("TS_UNACCEPT", "Traffic Selectors Unacceptable")),
    (NOTIFY_TYPE_INVALID_SELECTORS, 39u16, ("INVALID_SELECT", "Invalid Selectors")),
    (NOTIFY_TYPE_NAT_DETECTION_SOURCE_IP, 16388u16, ("NATD_S_IP", "NAT Detection Source IP")),
    (NOTIFY_TYPE_NAT_DETECTION_DESTINATION_IP, 16389u16, ("NATD_D_IP", "NAT Detection Destination IP")),
    (NOTIFY_TYPE_COOKIE, 16390u16, ("COOKIE", "Cookie")),
    (NOTIFY_TYPE_USE_TRANSPORT_MODE, 16391u16, ("USE_TRANSPORT_MODE", "Use Transport Mode")),
    (NOTIFY_TYPE_INITIAL_CONTACT, 16384u16, ("INIT_CONTACT", "Initial Contact")),
    (NOTIFY_TYPE_EAP_ONLY_AUTHENTICATION, 16417u16, ("EAP_ONLY", "EAP Only Authentication")),
    (NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED, 16420u16, ("MSG_ID_SYN_SUP", "IKEv2 Message ID Sync Supported")),
    (NOTIFY_TYPE_IKEV2_MESSAGE_ID_SYNC, 16422u16, ("MSG_ID_SYN", "IKEv2 Message ID Sync")),
    (NOTIFY_TYPE_ADDITIONAL_TS_POSSIBLE, 16386u16, ("ADDITIONAL_TS_POSSIBLE", "Additional Traffic Selectors Possible")),
    (NOTIFY_TYPE_IPCOMP_SUPPORTED, 16387u16, ("IPCOMP_SUPPORTED", "IPComp Supported")),
    (NOTIFY_TYPE_ESP_TFC_PADDING_NOT_SUPPORTED, 16394u16, ("ESP_TFC_PADDING_NOT_SUPPORTED", "ESP TFC Padding Not Supported")),
    (NOTIFY_TYPE_NON_FIRST_FRAGMENTS_ALSO, 16395u16, ("NON_FIRST_FRAGMENTS_ALSO", "Non-First Fragments Also")),
    (NOTIFY_TYPE_MOBIKE_SUPPORTED, 16396u16, ("MOBIKE_SUP", "MOBIKE Supported")),
    (NOTIFY_TYPE_NO_ADDITIONAL_ADDRESSES, 16399u16, ("NO_ADD_ADDR", "No Additional Addresses")),
    (NOTIFY_TYPE_MULTIPLE_AUTH_SUPPORTED, 16404u16, ("MULT_AUTH", "Multiple Authentication Supported")),
    (NOTIFY_TYPE_FRAGMENTATION_SUPPORTED, 16430u16, ("FRAG_SUP", "Fragmentation Supported")),
    (NOTIFY_TYPE_SIGNATURE_HASH_ALGORITHMS, 16431u16, ("SIG_HASH_ALGS", "Signature Hash Algorithms")),
    (NOTIFY_TYPE_INTERMEDIATE_EXCHANGE_SUPPORTED, 16438u16, ("INTERMEDIATE_EXCHANGE_SUPPORTED", "Intermediate Exchange Supported")),
}

// configs
const_variant! {
    CFG_TYPE_NAMES, u8, NameInfo:
    (CFG_TYPE_REQUEST, 1u8, ("REQUEST", "Configuration Request")),
    (CFG_TYPE_REPLY, 2u8, ("REPLY", "Configuration Reply")),
}

const_variant! {
    CP_ATTR_NAMES, u16, NameInfo:
    (CONFIG_ATTR_INTERNAL_IP4_ADDRESS, 1u16, ("ADDR", "Internal IPv4 Address")),
    (CONFIG_ATTR_INTERNAL_IP4_DNS, 3u16, ("DNS", "Internal IPv4 DNS")),
    (CONFIG_ATTR_INTERNAL_IP6_ADDRESS, 8u16, ("ADDR6", "Internal IPv6 Address")),
    (CONFIG_ATTR_INTERNAL_IP6_DNS, 10u16, ("DNS6", "Internal IPv6 DNS")),
}
