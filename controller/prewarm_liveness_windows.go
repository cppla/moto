//go:build windows

package controller

import "net"

// A raw synchronous recv can block on Go's Windows IOCP socket, while an
// already-expired deadline can miss a pending FIN/RST. Until a non-consuming,
// runtime-safe probe is available, Windows conservatively disables reuse and
// uses ordinary fresh dials.
const prewarmReuseSupported = false

func prewarmConnReusable(net.Conn) bool { return false }
