package controller

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	tlsRecordHeaderLength       = 5
	tlsHandshakeHeaderLength    = 4
	tlsMaxPlaintextRecordLength = 1 << 14
	tlsRecordTypeHandshake      = 22
	tlsHandshakeTypeClientHello = 1
	tlsExtensionServerName      = 0
	tlsExtensionALPN            = 16
	tlsServerNameTypeHostName   = 0
	tlsClientHelloMaxExtensions = 256
	tlsClientHelloMaxALPN       = 256
	tlsServerNameMaxLength      = 253
	tlsDNSLabelMaxLength        = 63
)

var (
	errTLSClientHelloMalformed = errors.New("malformed TLS ClientHello")
	errTLSClientHelloTooLarge  = errors.New("TLS ClientHello exceeds probe limit")
	errTLSClientHelloTruncated = errors.New("truncated TLS ClientHello")
)

// tlsClientHelloProbe contains the routing fields and every byte consumed from
// the input. A caller can forward Raw and then continue copying from the same
// reader without terminating TLS or changing the byte stream. Raw is populated
// on error as well, which permits a caller to apply a fallback route safely.
type tlsClientHelloProbe struct {
	ServerName    string
	ALPNProtocols []string
	Raw           []byte
}

// readTLSClientHello incrementally reads one ClientHello from TLS handshake
// records. maxBytes is supplied by the caller and bounds all reads and retained
// input. Deadlines and cancellation are deliberately left to the reader's
// owner, for example by setting a deadline on a net.Conn.
func readTLSClientHello(r io.Reader, maxBytes int) (tlsClientHelloProbe, error) {
	var probe tlsClientHelloProbe
	if r == nil {
		return probe, malformedTLSClientHello("nil reader")
	}
	if maxBytes <= 0 {
		return probe, fmt.Errorf("%w: limit must be positive", errTLSClientHelloTooLarge)
	}

	var handshake []byte
	for {
		var header [tlsRecordHeaderLength]byte
		if err := readTLSClientHelloBytes(r, header[:], maxBytes, &probe.Raw); err != nil {
			return probe, err
		}
		if header[0] != tlsRecordTypeHandshake {
			return probe, malformedTLSClientHello("record type %d is not handshake", header[0])
		}
		if header[1] != 3 {
			return probe, malformedTLSClientHello("record version %d.%d is not TLS", header[1], header[2])
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:]))
		if recordLength > tlsMaxPlaintextRecordLength {
			return probe, malformedTLSClientHello("record length %d exceeds %d", recordLength, tlsMaxPlaintextRecordLength)
		}
		if recordLength > maxBytes-len(probe.Raw) {
			return probe, fmt.Errorf("%w: record requires %d more bytes", errTLSClientHelloTooLarge, recordLength)
		}

		payload := make([]byte, recordLength)
		if err := readTLSClientHelloBytes(r, payload, maxBytes, &probe.Raw); err != nil {
			return probe, err
		}
		// The maxBytes check above also proves this addition cannot overflow an int.
		handshake = append(handshake, payload...)
		if len(handshake) < tlsHandshakeHeaderLength {
			continue
		}
		if handshake[0] != tlsHandshakeTypeClientHello {
			return probe, malformedTLSClientHello("handshake type %d is not ClientHello", handshake[0])
		}

		bodyLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		totalLength := tlsHandshakeHeaderLength + bodyLength
		if totalLength > maxBytes {
			return probe, fmt.Errorf("%w: declared handshake length is %d", errTLSClientHelloTooLarge, totalLength)
		}
		if len(handshake) < totalLength {
			continue
		}

		serverName, protocols, err := parseTLSClientHelloBody(handshake[tlsHandshakeHeaderLength:totalLength])
		if err != nil {
			return probe, err
		}
		probe.ServerName = serverName
		probe.ALPNProtocols = protocols
		return probe, nil
	}
}

func readTLSClientHelloBytes(r io.Reader, dst []byte, maxBytes int, raw *[]byte) error {
	if len(dst) > maxBytes-len(*raw) {
		return fmt.Errorf("%w: need %d more bytes", errTLSClientHelloTooLarge, len(dst))
	}
	n, err := io.ReadFull(r, dst)
	*raw = append(*raw, dst[:n]...)
	if err != nil {
		return fmt.Errorf("%w: %w", errTLSClientHelloTruncated, err)
	}
	return nil
}

func parseTLSClientHelloBody(body []byte) (string, []string, error) {
	cursor := tlsClientHelloCursor{data: body}
	legacyVersion, ok := cursor.take(2)
	if !ok {
		return "", nil, malformedTLSClientHello("missing legacy version")
	}
	if legacyVersion[0] != 3 {
		return "", nil, malformedTLSClientHello("legacy version %d.%d is not TLS", legacyVersion[0], legacyVersion[1])
	}
	if _, ok := cursor.take(32); !ok {
		return "", nil, malformedTLSClientHello("missing random")
	}

	sessionIDLength, ok := cursor.uint8()
	if !ok {
		return "", nil, malformedTLSClientHello("missing session ID length")
	}
	if sessionIDLength > 32 {
		return "", nil, malformedTLSClientHello("session ID length %d exceeds 32", sessionIDLength)
	}
	if _, ok := cursor.take(sessionIDLength); !ok {
		return "", nil, malformedTLSClientHello("truncated session ID")
	}

	cipherSuitesLength, ok := cursor.uint16()
	if !ok {
		return "", nil, malformedTLSClientHello("missing cipher suites length")
	}
	if cipherSuitesLength == 0 || cipherSuitesLength%2 != 0 {
		return "", nil, malformedTLSClientHello("invalid cipher suites length %d", cipherSuitesLength)
	}
	if _, ok := cursor.take(cipherSuitesLength); !ok {
		return "", nil, malformedTLSClientHello("truncated cipher suites")
	}

	compressionMethodsLength, ok := cursor.uint8()
	if !ok {
		return "", nil, malformedTLSClientHello("missing compression methods length")
	}
	if compressionMethodsLength == 0 {
		return "", nil, malformedTLSClientHello("empty compression methods")
	}
	if _, ok := cursor.take(compressionMethodsLength); !ok {
		return "", nil, malformedTLSClientHello("truncated compression methods")
	}

	// Extensions were optional before TLS 1.2, so an otherwise complete legacy
	// ClientHello without the extensions_length field is valid.
	if cursor.remaining() == 0 {
		return "", nil, nil
	}
	extensionsLength, ok := cursor.uint16()
	if !ok {
		return "", nil, malformedTLSClientHello("truncated extensions length")
	}
	if extensionsLength != cursor.remaining() {
		return "", nil, malformedTLSClientHello("extensions length %d does not match %d bytes", extensionsLength, cursor.remaining())
	}
	extensions, _ := cursor.take(extensionsLength)
	return parseTLSClientHelloExtensions(extensions)
}

func parseTLSClientHelloExtensions(extensions []byte) (string, []string, error) {
	cursor := tlsClientHelloCursor{data: extensions}
	seen := make(map[int]struct{})
	var serverName string
	var protocols []string
	extensionCount := 0
	for cursor.remaining() > 0 {
		extensionType, ok := cursor.uint16()
		if !ok {
			return "", nil, malformedTLSClientHello("truncated extension type")
		}
		extensionLength, ok := cursor.uint16()
		if !ok {
			return "", nil, malformedTLSClientHello("truncated extension length")
		}
		extensionCount++
		if extensionCount > tlsClientHelloMaxExtensions {
			return "", nil, fmt.Errorf("%w: more than %d extensions", errTLSClientHelloTooLarge, tlsClientHelloMaxExtensions)
		}
		extension, ok := cursor.take(extensionLength)
		if !ok {
			return "", nil, malformedTLSClientHello("extension %d is truncated", extensionType)
		}
		if _, duplicate := seen[extensionType]; duplicate {
			return "", nil, malformedTLSClientHello("duplicate extension %d", extensionType)
		}
		seen[extensionType] = struct{}{}

		switch extensionType {
		case tlsExtensionServerName:
			var err error
			serverName, err = parseTLSServerNameExtension(extension)
			if err != nil {
				return "", nil, err
			}
		case tlsExtensionALPN:
			var err error
			protocols, err = parseTLSALPNExtension(extension)
			if err != nil {
				return "", nil, err
			}
		}
	}
	return serverName, protocols, nil
}

func parseTLSServerNameExtension(extension []byte) (string, error) {
	cursor := tlsClientHelloCursor{data: extension}
	listLength, ok := cursor.uint16()
	if !ok {
		return "", malformedTLSClientHello("server_name list length is truncated")
	}
	if listLength == 0 || listLength != cursor.remaining() {
		return "", malformedTLSClientHello("server_name list length %d does not match %d bytes", listLength, cursor.remaining())
	}

	var serverName string
	hasHostName := false
	for cursor.remaining() > 0 {
		nameType, ok := cursor.uint8()
		if !ok {
			return "", malformedTLSClientHello("server_name type is truncated")
		}
		nameLength, ok := cursor.uint16()
		if !ok {
			return "", malformedTLSClientHello("server_name length is truncated")
		}
		if nameLength == 0 {
			return "", malformedTLSClientHello("server_name is empty")
		}
		name, ok := cursor.take(nameLength)
		if !ok {
			return "", malformedTLSClientHello("server_name is truncated")
		}
		if nameType != tlsServerNameTypeHostName {
			continue
		}
		if hasHostName {
			return "", malformedTLSClientHello("duplicate host_name entry")
		}
		if err := validateTLSClientHelloServerName(name); err != nil {
			return "", err
		}
		serverName = string(name)
		hasHostName = true
	}
	return serverName, nil
}

func parseTLSALPNExtension(extension []byte) ([]string, error) {
	cursor := tlsClientHelloCursor{data: extension}
	listLength, ok := cursor.uint16()
	if !ok {
		return nil, malformedTLSClientHello("ALPN list length is truncated")
	}
	if listLength == 0 || listLength != cursor.remaining() {
		return nil, malformedTLSClientHello("ALPN list length %d does not match %d bytes", listLength, cursor.remaining())
	}

	protocols := make([]string, 0, 2)
	for cursor.remaining() > 0 {
		protocolLength, ok := cursor.uint8()
		if !ok {
			return nil, malformedTLSClientHello("ALPN protocol length is truncated")
		}
		if len(protocols) >= tlsClientHelloMaxALPN {
			return nil, fmt.Errorf("%w: more than %d ALPN protocols", errTLSClientHelloTooLarge, tlsClientHelloMaxALPN)
		}
		if protocolLength == 0 {
			return nil, malformedTLSClientHello("ALPN protocol is empty")
		}
		protocol, ok := cursor.take(protocolLength)
		if !ok {
			return nil, malformedTLSClientHello("ALPN protocol is truncated")
		}
		protocols = append(protocols, string(protocol))
	}
	return protocols, nil
}

func validateTLSClientHelloServerName(name []byte) error {
	if len(name) == 0 || len(name) > tlsServerNameMaxLength {
		return malformedTLSClientHello("host_name must be a non-empty DNS name no longer than %d bytes", tlsServerNameMaxLength)
	}

	labelLength := 0
	for index, b := range name {
		if b == '.' {
			if labelLength == 0 || name[index-1] == '-' {
				return malformedTLSClientHello("host_name contains an invalid DNS label")
			}
			labelLength = 0
			continue
		}
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' {
			return malformedTLSClientHello("host_name contains a non-DNS ASCII byte")
		}
		if labelLength == 0 && b == '-' {
			return malformedTLSClientHello("host_name contains an invalid DNS label")
		}
		labelLength++
		if labelLength > tlsDNSLabelMaxLength {
			return malformedTLSClientHello("host_name contains a DNS label longer than %d bytes", tlsDNSLabelMaxLength)
		}
	}
	if labelLength == 0 || name[len(name)-1] == '-' {
		return malformedTLSClientHello("host_name contains an invalid DNS label")
	}
	return nil
}

type tlsClientHelloCursor struct {
	data   []byte
	offset int
}

func (cursor *tlsClientHelloCursor) remaining() int {
	return len(cursor.data) - cursor.offset
}

func (cursor *tlsClientHelloCursor) take(length int) ([]byte, bool) {
	// Subtraction rather than offset+length keeps hostile lengths from wrapping.
	if length < 0 || length > cursor.remaining() {
		return nil, false
	}
	value := cursor.data[cursor.offset : cursor.offset+length]
	cursor.offset += length
	return value, true
}

func (cursor *tlsClientHelloCursor) uint8() (int, bool) {
	value, ok := cursor.take(1)
	if !ok {
		return 0, false
	}
	return int(value[0]), true
}

func (cursor *tlsClientHelloCursor) uint16() (int, bool) {
	value, ok := cursor.take(2)
	if !ok {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(value)), true
}

func malformedTLSClientHello(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errTLSClientHelloMalformed, fmt.Sprintf(format, args...))
}
