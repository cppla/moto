module moto

go 1.27.2

// QUIC ClientHello lifecycle compatibility and the Go 1.27.2 TLS security backport.
replace github.com/refraction-networking/utls => github.com/cppla/utls v0.0.0-20261009031926-14c2a4cb1403

// Preserve QUIC CRYPTO offsets and buffer ownership across HelloRetryRequest.
// Session resumption remains disabled in Moto's production transports.
replace github.com/apernet/quic-go => github.com/cppla/quic-go v0.63.1-0.20261009113701-3a0e2cdb87a8

require (
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c
	github.com/refraction-networking/utls v1.8.3-0.20261006222701-ff1b50fbbe9a
	go.uber.org/zap v1.28.0
	golang.org/x/net v0.60.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
