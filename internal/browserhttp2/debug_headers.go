package http2

// debugHeaderValue supplies the value for log output only.
func debugHeaderValue(name, value string) string {
	if asciiEqualFold(name, "authorization") || asciiEqualFold(name, "proxy-authorization") {
		return "[REDACTED]"
	}
	return value
}
