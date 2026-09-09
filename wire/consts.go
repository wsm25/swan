package wire

// Protocol constants for RFC 7296 IKEv2 and its common extensions
// (RFC 7383 NAT-D, RFC 5996/7296 CP, RFC 7383/6311-ish fragmentation).
//
// Human-readable names for these numbers live exclusively in swan/debug;
// protocol logic switches on the typed constants below.

// Header / payload envelope numbers.
const (
	HeaderLen         = 28
	PayloadHeaderLen  = 4
	SkfHeaderLen      = 4
	IKEDefaultVersion = 0x20
)

// IKE header flag bits (RFC 7296 section 3.1).
const (
	FlagInitiator = 0x08
	FlagVersion   = 0x10
	FlagResponse  = 0x20
)

// Flags is the IKE header flag byte.
type Flags uint8

// PayloadType names payload bodies in the payload chain.
type PayloadType uint8

const (
	PayloadTypeNone   PayloadType = 0  // No Next Payload
	PayloadTypeSA     PayloadType = 33 // Security Association
	PayloadTypeKE     PayloadType = 34 // Key Exchange
	PayloadTypeIDi    PayloadType = 35 // Identification - Initiator
	PayloadTypeIDr    PayloadType = 36 // Identification - Responder
	PayloadTypeCert   PayloadType = 37 // Certificate
	PayloadTypeAuth   PayloadType = 39 // Authentication
	PayloadTypeNonce  PayloadType = 40 // Nonce
	PayloadTypeNotify PayloadType = 41 // Notify
	PayloadTypeDelete PayloadType = 42 // Delete
	PayloadTypeTSi    PayloadType = 44 // Traffic Selector - Initiator
	PayloadTypeTSr    PayloadType = 45 // Traffic Selector - Responder
	PayloadTypeSK     PayloadType = 46 // Encrypted and Authenticated
	PayloadTypeCP     PayloadType = 47 // Configuration
	PayloadTypeEAP    PayloadType = 48 // Extensible Authentication
	PayloadTypeSKF    PayloadType = 53 // Encrypted and Authenticated Fragment
)

// ExchangeType names the IKE exchange.
type ExchangeType uint8

const (
	ExchangeIkeSAInit     ExchangeType = 34
	ExchangeIkeAuth       ExchangeType = 35
	ExchangeCreateChild   ExchangeType = 36
	ExchangeInformational ExchangeType = 37
)

// IDType is the identification payload type field.
type IDType uint8

const (
	IDIPv4Addr   IDType = 1
	IDFqdn       IDType = 2
	IDRfc822Addr IDType = 3
	IDIPv6Addr   IDType = 5
	IDKeyID      IDType = 11
)

// CertEncoding is the CERT payload encoding field.
type CertEncoding uint8

const (
	CertEncodingX509Signature CertEncoding = 4
)

// AuthMethod is the AUTH payload method field.
type AuthMethod uint8

const (
	AuthRsaDigitalSignature AuthMethod = 1
	AuthSharedKeyMIC        AuthMethod = 2
	AuthDssDigitalSignature AuthMethod = 3
	AuthDigitalSignature    AuthMethod = 14 // RFC 7427
)

// NotifyType is the NOTIFY payload message type.
type NotifyType uint16

const (
	NotifyNoProposalChosen              NotifyType = 14
	NotifyInvalidKePayload              NotifyType = 17
	NotifyAuthenticationFailed          NotifyType = 24
	NotifySinglePairRequired            NotifyType = 34
	NotifyNoAdditionalSAs               NotifyType = 35
	NotifyInternalAddressFailure        NotifyType = 36
	NotifyTemporaryFailure              NotifyType = 43
	NotifyChildSANotFound               NotifyType = 44
	NotifyFailedCPRequired              NotifyType = 37
	NotifyTSUnacceptable                NotifyType = 38
	NotifyInvalidSelectors              NotifyType = 39
	NotifyInitialContact                NotifyType = 16384
	NotifyAdditionalTSPossible          NotifyType = 16386
	NotifyIPCompSupported               NotifyType = 16387
	NotifyNATDetectionSourceIP          NotifyType = 16388
	NotifyNATDetectionDestinationIP     NotifyType = 16389
	NotifyCookie                        NotifyType = 16390
	NotifyUseTransportMode              NotifyType = 16391
	NotifyEspTFCPaddingNotSupported     NotifyType = 16394
	NotifyNonFirstFragmentsAlso         NotifyType = 16395
	NotifyMobikeSupported               NotifyType = 16396
	NotifyNoAdditionalAddresses         NotifyType = 16399
	NotifyMultipleAuthSupported         NotifyType = 16404
	NotifyEapOnlyAuthentication         NotifyType = 16417
	NotifyIKEv2MessageIDSyncSupported   NotifyType = 16420
	NotifyIKEv2MessageIDSync            NotifyType = 16422
	NotifyFragmentationSupported        NotifyType = 16430
	NotifySignatureHashAlgorithms       NotifyType = 16431
	NotifyRekeySA                       NotifyType = 16393
	NotifyIntermediateExchangeSupported NotifyType = 16438
)

// Notify protocol-id / SPI scoping rules (validated by payload.Notify).
const (
	NotifyProtocolNone = 0
)

// Delete protocol IDs.
const (
	DeleteProtocolIKE = 1
	DeleteProtocolAH  = 2
	DeleteProtocolESP = 3
)

// TransformType names SA transform substructures.
type TransformType uint8

const (
	TransformENC   TransformType = 1
	TransformPRF   TransformType = 2
	TransformINTEG TransformType = 3
	TransformDH    TransformType = 4
	TransformESN   TransformType = 5
)

// Transform / proposal chaining values.
const (
	TransformChainLast = 0
	ProposalChainMore  = 2
	TransformChainMore = 3
)

// Transform attribute encoding (RFC 7296 3.3.5).
const (
	TransformAttrKeyLength = 14
	TransformAttrFormatTV  = 0x8000
)

// ESN mode advertised by the MVP (no extended sequence numbers).
const (
	ESNNoExtendedSequenceNumbers = 0
)

// Configuration payload types and attribute numbers (RFC 7296 2.19/3.15).
const (
	ConfigTypeRequest = 1
	ConfigTypeReply   = 2

	ConfigAttrInternalIPv4Address   = 1
	ConfigAttrInternalIPv4DNS       = 3
	ConfigAttrInternalAddressExpiry = 5
	ConfigAttrInternalIPv6Address   = 8
	ConfigAttrInternalIPv6DNS       = 10
)

// Traffic selector types (RFC 7296 3.13).
const (
	TSTypeIPv4AddrRange = 7
	TSTypeIPv6AddrRange = 8
)
