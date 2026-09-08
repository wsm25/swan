package payload

import "swan/wire"

// EAP payloads are opaque to the IKE layer: the body is a complete EAP
// packet, parsed and produced exclusively by swan/eap. This file exists so
// the per-payload codec surface stays complete; there are intentionally no
// EAP-specific encode/decode helpers here.
//
// Routing rule used by swan/control: in bootstrap/final IKE_AUTH responses
// the EAP body is forwarded verbatim to the eap worker mailbox; conversely
// eap worker responses are wrapped verbatim into protected IKE_AUTH
// requests.

var _ = wire.PayloadTypeEAP
