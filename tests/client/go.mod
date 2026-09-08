// swan4 debug client: real UDP wire -> swan stream framing -> swan library.
module swan4-tests

go 1.24

require swan v0.0.0

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

replace swan => ../..
