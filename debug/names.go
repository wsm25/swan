// Package debug hosts the centralized human-friendly protocol formatting
// used at packet and parse boundaries. Behavior of the library must never
// depend on this package: it only stringifies and logs.
//
// Name maps live here and nowhere else (payload types, exchange types,
// notify types, ID types, transform types, CP attributes, EAP codes/types,
// stages): protocol logic switches on the typed constants in swan/wire,
// logging asks this package for the name.
package debug

import (
	"fmt"

	"github.com/wsm25/swan/events"
	"github.com/wsm25/swan/transport"
	"github.com/wsm25/swan/wire"
)

// PayloadName maps a payload type to its short protocol name ("SA", "SK"...).
func PayloadName(t wire.PayloadType) string {
	switch t {
	case wire.PayloadTypeNone:
		return "NONE"
	case wire.PayloadTypeSA:
		return "SA"
	case wire.PayloadTypeKE:
		return "KE"
	case wire.PayloadTypeIDi:
		return "IDi"
	case wire.PayloadTypeIDr:
		return "IDr"
	case wire.PayloadTypeCert:
		return "CERT"
	case wire.PayloadTypeAuth:
		return "AUTH"
	case wire.PayloadTypeNonce:
		return "N"
	case wire.PayloadTypeNotify:
		return "NOTIFY"
	case wire.PayloadTypeDelete:
		return "DELETE"
	case wire.PayloadTypeTSi:
		return "TSi"
	case wire.PayloadTypeTSr:
		return "TSr"
	case wire.PayloadTypeSK:
		return "SK"
	case wire.PayloadTypeCP:
		return "CP"
	case wire.PayloadTypeEAP:
		return "EAP"
	case wire.PayloadTypeSKF:
		return "SKF"
	default:
		return fmt.Sprintf("#0x%x", uint8(t))
	}
}

// ExchangeName maps an exchange type to its short name ("IKE_SA_INIT"...).
func ExchangeName(t wire.ExchangeType) string {
	switch t {
	case wire.ExchangeIkeSAInit:
		return "IKE_SA_INIT"
	case wire.ExchangeIkeAuth:
		return "IKE_AUTH"
	case wire.ExchangeCreateChild:
		return "CREATE_CHILD_SA"
	case wire.ExchangeInformational:
		return "INFORMATIONAL"
	default:
		return fmt.Sprintf("#0x%x", uint8(t))
	}
}

// IDTypeName maps an ID payload type ("FQDN", "RFC822_ADDR"...).
func IDTypeName(t wire.IDType) string {
	switch t {
	case wire.IDIPv4Addr:
		return "IPV4_ADDR"
	case wire.IDFqdn:
		return "FQDN"
	case wire.IDRfc822Addr:
		return "RFC822_ADDR"
	case wire.IDIPv6Addr:
		return "IPV6_ADDR"
	case wire.IDKeyID:
		return "KEY_ID"
	default:
		return fmt.Sprintf("#0x%x", uint8(t))
	}
}

// CertEncodingName maps a CERT encoding byte ("X509_SIGNATURE"...).
func CertEncodingName(enc uint8) string {
	switch wire.CertEncoding(enc) {
	case wire.CertEncodingX509Signature:
		return "X509_SIGNATURE"
	default:
		return fmt.Sprintf("#0x%x", enc)
	}
}

// AuthMethodName maps an AUTH method ("SHARED_KEY_MIC",
// "DIGITAL_SIGNATURE"...).
func AuthMethodName(m uint8) string {
	switch wire.AuthMethod(m) {
	case wire.AuthRsaDigitalSignature:
		return "RSA_DIGITAL_SIGNATURE"
	case wire.AuthSharedKeyMIC:
		return "SHARED_KEY_MIC"
	case wire.AuthDssDigitalSignature:
		return "DSS_DIGITAL_SIGNATURE"
	case wire.AuthDigitalSignature:
		return "DIGITAL_SIGNATURE"
	default:
		return fmt.Sprintf("#0x%x", m)
	}
}

// NotifyName maps a NOTIFY type ("COOKIE", "NAT_DETECTION_SOURCE_IP"...).
func NotifyName(t wire.NotifyType) string {
	switch t {
	case wire.NotifyNoProposalChosen:
		return "NO_PROPOSAL_CHOSEN"
	case wire.NotifyInvalidKePayload:
		return "INVALID_KE_PAYLOAD"
	case wire.NotifyAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case wire.NotifySinglePairRequired:
		return "SINGLE_PAIR_REQUIRED"
	case wire.NotifyNoAdditionalSAs:
		return "NO_ADDITIONAL_SAS"
	case wire.NotifyInternalAddressFailure:
		return "INTERNAL_ADDRESS_FAILURE"
	case wire.NotifyFailedCPRequired:
		return "FAILED_CP_REQUIRED"
	case wire.NotifyTSUnacceptable:
		return "TS_UNACCEPTABLE"
	case wire.NotifyInvalidSelectors:
		return "INVALID_SELECTORS"
	case wire.NotifyInitialContact:
		return "INITIAL_CONTACT"
	case wire.NotifyAdditionalTSPossible:
		return "ADDITIONAL_TS_POSSIBLE"
	case wire.NotifyIPCompSupported:
		return "IPCOMP_SUPPORTED"
	case wire.NotifyNATDetectionSourceIP:
		return "NAT_DETECTION_SOURCE_IP"
	case wire.NotifyNATDetectionDestinationIP:
		return "NAT_DETECTION_DESTINATION_IP"
	case wire.NotifyCookie:
		return "COOKIE"
	case wire.NotifyUseTransportMode:
		return "USE_TRANSPORT_MODE"
	case wire.NotifyEspTFCPaddingNotSupported:
		return "ESP_TFC_PADDING_NOT_SUPPORTED"
	case wire.NotifyNonFirstFragmentsAlso:
		return "NON_FIRST_FRAGMENTS_ALSO"
	case wire.NotifyMobikeSupported:
		return "MOBIKE_SUPPORTED"
	case wire.NotifyNoAdditionalAddresses:
		return "NO_ADDITIONAL_ADDRESSES"
	case wire.NotifyMultipleAuthSupported:
		return "MULTIPLE_AUTH_SUPPORTED"
	case wire.NotifyEapOnlyAuthentication:
		return "EAP_ONLY_AUTHENTICATION"
	case wire.NotifyIKEv2MessageIDSyncSupported:
		return "IKEV2_MESSAGE_ID_SYNC_SUPPORTED"
	case wire.NotifyIKEv2MessageIDSync:
		return "IKEV2_MESSAGE_ID_SYNC"
	case wire.NotifyFragmentationSupported:
		return "FRAGMENTATION_SUPPORTED"
	case wire.NotifySignatureHashAlgorithms:
		return "SIGNATURE_HASH_ALGORITHMS"
	case wire.NotifyIntermediateExchangeSupported:
		return "INTERMEDIATE_EXCHANGE_SUPPORTED"
	default:
		return fmt.Sprintf("#%d", uint16(t))
	}
}

// TransformTypeName maps a transform type ("ENCR", "PRF", "INTEG", "DH"...).
func TransformTypeName(t wire.TransformType) string {
	switch t {
	case wire.TransformENC:
		return "ENCR"
	case wire.TransformPRF:
		return "PRF"
	case wire.TransformINTEG:
		return "INTEG"
	case wire.TransformDH:
		return "DH"
	case wire.TransformESN:
		return "ESN"
	default:
		return fmt.Sprintf("#0x%x", uint8(t))
	}
}

// ConfigTypeName maps a CP payload kind ("CFG_REQUEST"...).
func ConfigTypeName(t wire.ConfigType) string {
	switch t {
	case wire.ConfigTypeRequest:
		return "CFG_REQUEST"
	case wire.ConfigTypeReply:
		return "CFG_REPLY"
	case wire.ConfigTypeSet:
		return "CFG_SET"
	case wire.ConfigTypeAck:
		return "CFG_ACK"
	default:
		return fmt.Sprintf("#%d", uint8(t))
	}
}

// ConfigAttributeName maps a CP attribute ("INTERNAL_IP4_ADDRESS"...).
func ConfigAttributeName(t uint16) string {
	switch t {
	case wire.ConfigAttrInternalIPv4Address:
		return "INTERNAL_IP4_ADDRESS"
	case wire.ConfigAttrInternalIPv4DNS:
		return "INTERNAL_IP4_DNS"
	case wire.ConfigAttrInternalIPv6Address:
		return "INTERNAL_IP6_ADDRESS"
	case wire.ConfigAttrInternalIPv6DNS:
		return "INTERNAL_IP6_DNS"
	default:
		return fmt.Sprintf("#%d", t)
	}
}

// EAPCodeName maps an EAP code byte ("REQUEST", "SUCCESS"...).
func EAPCodeName(c uint8) string {
	switch c {
	case 1:
		return "REQUEST"
	case 2:
		return "RESPONSE"
	case 3:
		return "SUCCESS"
	case 4:
		return "FAILURE"
	default:
		return fmt.Sprintf("#0x%x", c)
	}
}

// EAPTypeName maps an EAP type byte ("IDENTITY", "PEAP", "MSCHAPV2"...).
func EAPTypeName(t uint8) string {
	switch t {
	case 1:
		return "IDENTITY"
	case 3:
		return "NAK"
	case 21:
		return "MSTLV"
	case 25:
		return "PEAP"
	case 26:
		return "MSCHAPV2"
	default:
		return fmt.Sprintf("#%d", t)
	}
}

// StageName maps an event stage to its short name.
func StageName(s events.Stage) string {
	switch s {
	case events.StageIKEInit:
		return "ike_init"
	case events.StageIKEAuth:
		return "ike_auth"
	case events.StageEAP:
		return "eap"
	case events.StageChildSA:
		return "child_sa"
	case events.StageRunning:
		return "running"
	default:
		return fmt.Sprintf("#%d", uint8(s))
	}
}

// FrameKindName maps a transport frame kind to its short name.
func FrameKindName(k transport.Kind) string {
	switch k {
	case transport.KindIKE:
		return "IKE"
	case transport.KindESP:
		return "ESP"
	case transport.KindKeepalive:
		return "NAT_KEEPALIVE"
	default:
		return fmt.Sprintf("#%d", uint8(k))
	}
}
