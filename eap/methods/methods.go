// Package methods is the EAP method registry: it maps configuration names
// ("peap", "mschapv2") onto concrete Method implementations and keeps the
// method packages free of each other.
package methods

import (
	"errors"

	"swan/eap"
	"swan/eap/mschapv2"
	"swan/eap/peap"
)

// Registered method names (must match eap.Config.Method values).
const (
	MethodPEAP     = "peap"
	MethodMSCHAPV2 = "mschapv2"
)

// New builds the configured method. PEAP receives the full option set and
// the inner MSCHAPv2 credentials; mschapv2 ignores TLS options. Unknown
// methods hard-fail (MVP profile: only these two exist).
func New(cfg *eap.Config) (eap.Method, error) {
	if cfg == nil {
		return nil, errors.New("swan/eap/methods: nil EAP configuration")
	}
	switch cfg.Method {
	case MethodPEAP:
		if cfg.ServerName == "" {
			return nil, errors.New("swan/eap/methods: PEAP requires cfg.ServerName")
		}
		opts := peap.Options{
			FragmentSize:         cfg.FragmentSize,
			MaxMessageCount:      cfg.MaxMessageCount,
			IncludeLength:        cfg.IncludeLength,
			StrongswanCompatible: cfg.StrongswanCompatible,
			InsecureSkipVerify:   cfg.InsecureSkipVerify,
		}
		return peap.New(cfg.ServerName, cfg.Identity, cfg.Password, opts)
	case MethodMSCHAPV2:
		return mschapv2.New(cfg.Identity, cfg.Password), nil
	default:
		return nil, errors.New("swan/eap/methods: unsupported EAP method " + cfg.Method)
	}
}

// compile-time guarantees that each method implements eap.Method.
var (
	_ eap.Method = (*peap.Method)(nil)
	_ eap.Method = (*mschapv2.Method)(nil)
)
