//go:build !darwin && !linux && !windows

package controller

import "net"

const prewarmReuseSupported = false

// Unknown platforms conservatively decline reuse rather than risk handing a
// visibly closed idle connection to a new client.
func prewarmConnReusable(net.Conn) bool {
	return false
}
