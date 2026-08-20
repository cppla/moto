package controller

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// The v1 specification limits a complete header, including CRLF, to 108
	// bytes. The v2 wire format permits a 64 KiB payload, but accepting that
	// much unauthenticated metadata per connection is unnecessary here. The
	// operational cap still leaves ample room for the IP address block and
	// ordinary TLVs while bounding both allocation and read amplification.
	proxyProtocolV1MaxHeaderLength  = 108
	proxyProtocolV2MaxPayloadLength = 4 << 10
)

var (
	proxyProtocolV1Signature = []byte("PROXY ")
	proxyProtocolV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")
)

type proxyProtocolVersion uint8

const (
	proxyProtocolVersion1 proxyProtocolVersion = 1
	proxyProtocolVersion2 proxyProtocolVersion = 2
)

type proxyProtocolCommand uint8

const (
	// UNKNOWN in v1 and LOCAL in v2 both deliberately carry no trusted peer
	// address. Version distinguishes their wire representation.
	proxyProtocolCommandLocal proxyProtocolCommand = iota
	proxyProtocolCommandProxy
)

type proxyProtocolHeader struct {
	Version     proxyProtocolVersion
	Command     proxyProtocolCommand
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// proxyProtocolReadResult keeps bytes consumed while deciding that a stream
// does not start with PROXY protocol. A caller must replay Replay before the
// remaining reader (for example with io.MultiReader) to preserve the original
// application byte stream. Header is non-nil only when a full, valid header was
// consumed.
type proxyProtocolReadResult struct {
	Header *proxyProtocolHeader
	Replay []byte
}

// readProxyProtocolHeader auto-detects PROXY protocol v1 and v2 without losing
// ordinary application data. Signature detection reads at most 12 bytes. Once
// a signature matches, truncated or malformed headers are errors rather than
// application data, preventing ambiguous spoofing fallbacks.
func readProxyProtocolHeader(reader io.Reader) (proxyProtocolReadResult, error) {
	if reader == nil {
		return proxyProtocolReadResult{}, errors.New("read PROXY protocol header: nil reader")
	}

	prefix := make([]byte, 0, len(proxyProtocolV2Signature))
	v1Candidate := true
	v2Candidate := true
	for v1Candidate || v2Candidate {
		var next [1]byte
		if _, err := io.ReadFull(reader, next[:]); err != nil {
			if len(prefix) == 0 && errors.Is(err, io.EOF) {
				return proxyProtocolReadResult{}, io.EOF
			}
			return proxyProtocolReadResult{}, fmt.Errorf(
				"read PROXY protocol signature: %w",
				proxyProtocolReadError(err),
			)
		}
		prefix = append(prefix, next[0])

		index := len(prefix) - 1
		v1Candidate = v1Candidate && index < len(proxyProtocolV1Signature) &&
			next[0] == proxyProtocolV1Signature[index]
		v2Candidate = v2Candidate && index < len(proxyProtocolV2Signature) &&
			next[0] == proxyProtocolV2Signature[index]

		if v1Candidate && len(prefix) == len(proxyProtocolV1Signature) {
			header, err := readProxyProtocolV1(reader)
			if err != nil {
				return proxyProtocolReadResult{}, err
			}
			return proxyProtocolReadResult{Header: &header}, nil
		}
		if v2Candidate && len(prefix) == len(proxyProtocolV2Signature) {
			header, err := readProxyProtocolV2(reader)
			if err != nil {
				return proxyProtocolReadResult{}, err
			}
			return proxyProtocolReadResult{Header: &header}, nil
		}
	}

	return proxyProtocolReadResult{Replay: prefix}, nil
}

func readProxyProtocolV1(reader io.Reader) (proxyProtocolHeader, error) {
	line := append([]byte(nil), proxyProtocolV1Signature...)
	for len(line) < proxyProtocolV1MaxHeaderLength {
		var next [1]byte
		if _, err := io.ReadFull(reader, next[:]); err != nil {
			return proxyProtocolHeader{}, fmt.Errorf(
				"read PROXY protocol v1 header: %w",
				proxyProtocolReadError(err),
			)
		}
		line = append(line, next[0])
		if len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n' {
			return parseProxyProtocolV1(line)
		}
	}
	return proxyProtocolHeader{}, fmt.Errorf("PROXY protocol v1 header exceeds %d bytes", proxyProtocolV1MaxHeaderLength)
}

func parseProxyProtocolV1(line []byte) (proxyProtocolHeader, error) {
	if len(line) < len(proxyProtocolV1Signature)+2 ||
		!bytes.HasPrefix(line, proxyProtocolV1Signature) ||
		line[len(line)-2] != '\r' || line[len(line)-1] != '\n' {
		return proxyProtocolHeader{}, errors.New("malformed PROXY protocol v1 header framing")
	}

	body := string(line[len(proxyProtocolV1Signature) : len(line)-2])
	if body == "UNKNOWN" || strings.HasPrefix(body, "UNKNOWN ") {
		return proxyProtocolHeader{
			Version: proxyProtocolVersion1,
			Command: proxyProtocolCommandLocal,
		}, nil
	}

	fields := strings.Split(body, " ")
	if len(fields) != 5 || (fields[0] != "TCP4" && fields[0] != "TCP6") {
		return proxyProtocolHeader{}, errors.New("malformed PROXY protocol v1 address tuple")
	}

	sourceAddr, err := parseProxyProtocolV1Address(fields[1], fields[0])
	if err != nil {
		return proxyProtocolHeader{}, fmt.Errorf("invalid PROXY protocol v1 source address: %w", err)
	}
	destinationAddr, err := parseProxyProtocolV1Address(fields[2], fields[0])
	if err != nil {
		return proxyProtocolHeader{}, fmt.Errorf("invalid PROXY protocol v1 destination address: %w", err)
	}
	sourcePort, err := parseProxyProtocolPort(fields[3])
	if err != nil {
		return proxyProtocolHeader{}, fmt.Errorf("invalid PROXY protocol v1 source port: %w", err)
	}
	destinationPort, err := parseProxyProtocolPort(fields[4])
	if err != nil {
		return proxyProtocolHeader{}, fmt.Errorf("invalid PROXY protocol v1 destination port: %w", err)
	}

	return proxyProtocolHeader{
		Version:     proxyProtocolVersion1,
		Command:     proxyProtocolCommandProxy,
		Source:      netip.AddrPortFrom(sourceAddr, sourcePort),
		Destination: netip.AddrPortFrom(destinationAddr, destinationPort),
	}, nil
}

func parseProxyProtocolV1Address(value, family string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errors.New("scoped IPv6 addresses are not supported")
	}
	if family == "TCP4" && !addr.Is4() {
		return netip.Addr{}, errors.New("address is not IPv4")
	}
	if family == "TCP6" && (!addr.Is6() || addr.Is4In6()) {
		return netip.Addr{}, errors.New("address is not native IPv6")
	}
	return addr, nil
}

func parseProxyProtocolPort(value string) (uint16, error) {
	if len(value) > 1 && value[0] == '0' {
		return 0, errors.New("port must not contain leading zeroes")
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
}

func readProxyProtocolV2(reader io.Reader) (proxyProtocolHeader, error) {
	var fixed [4]byte
	if _, err := io.ReadFull(reader, fixed[:]); err != nil {
		return proxyProtocolHeader{}, fmt.Errorf(
			"read PROXY protocol v2 fixed header: %w",
			proxyProtocolReadError(err),
		)
	}

	version := fixed[0] >> 4
	command := fixed[0] & 0x0f
	if version != 2 {
		return proxyProtocolHeader{}, fmt.Errorf("unsupported PROXY protocol v2 version %d", version)
	}
	if command != byte(proxyProtocolCommandLocal) && command != byte(proxyProtocolCommandProxy) {
		return proxyProtocolHeader{}, fmt.Errorf("unsupported PROXY protocol v2 command %d", command)
	}
	payloadLength := int(binary.BigEndian.Uint16(fixed[2:]))
	if payloadLength > proxyProtocolV2MaxPayloadLength {
		return proxyProtocolHeader{}, fmt.Errorf(
			"PROXY protocol v2 payload length %d exceeds limit %d",
			payloadLength, proxyProtocolV2MaxPayloadLength,
		)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return proxyProtocolHeader{}, fmt.Errorf(
			"read PROXY protocol v2 payload: %w",
			proxyProtocolReadError(err),
		)
	}
	if command == byte(proxyProtocolCommandLocal) {
		return proxyProtocolHeader{
			Version: proxyProtocolVersion2,
			Command: proxyProtocolCommandLocal,
		}, nil
	}
	addressLength, err := proxyProtocolV2AddressLength(command, fixed[1])
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	if payloadLength < addressLength {
		return proxyProtocolHeader{}, fmt.Errorf(
			"PROXY protocol v2 address payload is %d bytes, want at least %d",
			payloadLength, addressLength,
		)
	}

	header, err := parseProxyProtocolV2(command, fixed[1], payload)
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	header.Version = proxyProtocolVersion2
	return header, nil
}

func proxyProtocolV2AddressLength(command, familyProtocol byte) (int, error) {
	switch familyProtocol {
	case 0x00: // AF_UNSPEC / UNSPEC
		if command == byte(proxyProtocolCommandProxy) {
			return 0, errors.New("PROXY protocol v2 PROXY command requires TCP4 or TCP6")
		}
		return 0, nil
	case 0x11: // AF_INET / STREAM
		return 12, nil
	case 0x21: // AF_INET6 / STREAM
		return 36, nil
	default:
		return 0, fmt.Errorf("unsupported PROXY protocol v2 family/protocol 0x%02x", familyProtocol)
	}
}

func proxyProtocolReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func parseProxyProtocolV2(command byte, familyProtocol byte, payload []byte) (proxyProtocolHeader, error) {
	addressLength, err := proxyProtocolV2AddressLength(command, familyProtocol)
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	if len(payload) < addressLength {
		return proxyProtocolHeader{}, fmt.Errorf(
			"PROXY protocol v2 address payload is %d bytes, want at least %d",
			len(payload), addressLength,
		)
	}

	var source, destination netip.AddrPort

	switch familyProtocol {
	case 0x00: // AF_UNSPEC / UNSPEC
	case 0x11: // AF_INET / STREAM
		sourceAddr := netip.AddrFrom4([4]byte(payload[0:4]))
		destinationAddr := netip.AddrFrom4([4]byte(payload[4:8]))
		source = netip.AddrPortFrom(sourceAddr, binary.BigEndian.Uint16(payload[8:10]))
		destination = netip.AddrPortFrom(destinationAddr, binary.BigEndian.Uint16(payload[10:12]))
	case 0x21: // AF_INET6 / STREAM
		sourceAddr := netip.AddrFrom16([16]byte(payload[0:16]))
		destinationAddr := netip.AddrFrom16([16]byte(payload[16:32]))
		source = netip.AddrPortFrom(sourceAddr, binary.BigEndian.Uint16(payload[32:34]))
		destination = netip.AddrPortFrom(destinationAddr, binary.BigEndian.Uint16(payload[34:36]))
	}

	if err := validateProxyProtocolV2TLVs(payload[addressLength:]); err != nil {
		return proxyProtocolHeader{}, err
	}
	if command == byte(proxyProtocolCommandLocal) {
		return proxyProtocolHeader{Command: proxyProtocolCommandLocal}, nil
	}
	return proxyProtocolHeader{
		Command:     proxyProtocolCommandProxy,
		Source:      source,
		Destination: destination,
	}, nil
}

func validateProxyProtocolV2TLVs(payload []byte) error {
	for len(payload) > 0 {
		if len(payload) < 3 {
			return errors.New("malformed PROXY protocol v2 TLV header")
		}
		valueLength := int(binary.BigEndian.Uint16(payload[1:3]))
		if valueLength > len(payload)-3 {
			return errors.New("malformed PROXY protocol v2 TLV length")
		}
		payload = payload[3+valueLength:]
	}
	return nil
}

// writeProxyProtocolHeader writes a canonical v1 or v2 header. UNKNOWN/LOCAL
// is selected with proxyProtocolCommandLocal; address tuples are required only
// for the PROXY command.
func writeProxyProtocolHeader(writer io.Writer, header proxyProtocolHeader) error {
	if writer == nil {
		return errors.New("write PROXY protocol header: nil writer")
	}
	if header.Command != proxyProtocolCommandLocal && header.Command != proxyProtocolCommandProxy {
		return fmt.Errorf("unsupported PROXY protocol command %d", header.Command)
	}

	switch header.Version {
	case proxyProtocolVersion1:
		return writeProxyProtocolV1(writer, header)
	case proxyProtocolVersion2:
		return writeProxyProtocolV2(writer, header)
	default:
		return fmt.Errorf("unsupported PROXY protocol version %d", header.Version)
	}
}

func writeProxyProtocolV1(writer io.Writer, header proxyProtocolHeader) error {
	if header.Command == proxyProtocolCommandLocal {
		return writeProxyProtocolBytes(writer, []byte("PROXY UNKNOWN\r\n"))
	}

	family, err := validateProxyProtocolEndpoints(header.Source, header.Destination)
	if err != nil {
		return err
	}
	line := fmt.Sprintf(
		"PROXY %s %s %s %d %d\r\n",
		family,
		header.Source.Addr(),
		header.Destination.Addr(),
		header.Source.Port(),
		header.Destination.Port(),
	)
	if len(line) > proxyProtocolV1MaxHeaderLength {
		return fmt.Errorf("encoded PROXY protocol v1 header exceeds %d bytes", proxyProtocolV1MaxHeaderLength)
	}
	return writeProxyProtocolBytes(writer, []byte(line))
}

func writeProxyProtocolV2(writer io.Writer, header proxyProtocolHeader) error {
	encoded := make([]byte, 16, 16+36)
	copy(encoded, proxyProtocolV2Signature)
	encoded[12] = 0x20 | byte(header.Command)
	if header.Command == proxyProtocolCommandLocal {
		return writeProxyProtocolBytes(writer, encoded)
	}

	family, err := validateProxyProtocolEndpoints(header.Source, header.Destination)
	if err != nil {
		return err
	}
	switch family {
	case "TCP4":
		encoded[13] = 0x11
		binary.BigEndian.PutUint16(encoded[14:16], 12)
		source := header.Source.Addr().As4()
		destination := header.Destination.Addr().As4()
		encoded = append(encoded, source[:]...)
		encoded = append(encoded, destination[:]...)
	case "TCP6":
		encoded[13] = 0x21
		binary.BigEndian.PutUint16(encoded[14:16], 36)
		source := header.Source.Addr().As16()
		destination := header.Destination.Addr().As16()
		encoded = append(encoded, source[:]...)
		encoded = append(encoded, destination[:]...)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, header.Source.Port())
	encoded = binary.BigEndian.AppendUint16(encoded, header.Destination.Port())
	return writeProxyProtocolBytes(writer, encoded)
}

func validateProxyProtocolEndpoints(source, destination netip.AddrPort) (string, error) {
	if !source.IsValid() || !destination.IsValid() {
		return "", errors.New("PROXY protocol source and destination must both be valid")
	}
	if source.Addr().Zone() != "" || destination.Addr().Zone() != "" {
		return "", errors.New("PROXY protocol does not support scoped IPv6 addresses")
	}
	if source.Addr().Is4() && destination.Addr().Is4() {
		return "TCP4", nil
	}
	if source.Addr().Is6() && !source.Addr().Is4In6() &&
		destination.Addr().Is6() && !destination.Addr().Is4In6() {
		return "TCP6", nil
	}
	return "", errors.New("PROXY protocol source and destination address families must match")
}

func writeProxyProtocolBytes(writer io.Writer, payload []byte) error {
	written, err := writer.Write(payload)
	if err != nil {
		return fmt.Errorf("write PROXY protocol header: %w", err)
	}
	if written != len(payload) {
		return fmt.Errorf("write PROXY protocol header: %w", io.ErrShortWrite)
	}
	return nil
}
