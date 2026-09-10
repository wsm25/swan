// swan is a userspace, initiator-only IKEv2 (NAT-T) library written in Go.
//
// This module is intentionally backend-free:
//
// github.com/metacubex/utls (instead of refraction-networking/utls) keeps
// the Go directive at 1.20 and shares one uTLS implementation with mihomo,
// so consumers do not inherit a second TLS stack or a go-version bump.
//   - the wire is injected as an io.ReadWriteCloser (stream of length-prefixed
//     NAT-T datagrams, see swan/transport);
//   - the resulting tunnel is exposed as an io.ReadWriteCloser that carries
//     one raw IP packet per read/write operation.
module github.com/wsm25/swan

go 1.20

require github.com/metacubex/utls v1.8.7

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/sys v0.30.0 // indirect
)
