// swan is a userspace, initiator-only IKEv2 (NAT-T) library written in Go.
//
// This module is intentionally backend-free:
//   - the wire is injected as an io.ReadWriteCloser (stream of length-prefixed
//     NAT-T datagrams, see swan/transport);
//   - the resulting tunnel is exposed as an io.ReadWriteCloser that carries
//     one raw IP packet per read/write operation.
module swan

go 1.24

require github.com/refraction-networking/utls v1.8.2

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)
