//go:build darwin || linux

package controller

import (
	"errors"
	"net"
	"syscall"
)

const prewarmReuseSupported = true

// prewarmConnReusable peeks without consuming data. EAGAIN means the socket is
// still open but currently has no bytes; zero bytes means FIN, while any other
// error (including a pending RST) makes the idle connection unsafe to hand to a
// new client.
func prewarmConnReusable(conn net.Conn) bool {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return false
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return false
	}
	reusable := false
	err = rawConn.Control(func(fd uintptr) {
		var probe [1]byte
		n, _, recvErr := syscall.Recvfrom(int(fd), probe[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case recvErr == nil:
			reusable = n > 0
		case errors.Is(recvErr, syscall.EAGAIN), errors.Is(recvErr, syscall.EWOULDBLOCK):
			reusable = true
		default:
			reusable = false
		}
	})
	return err == nil && reusable
}
