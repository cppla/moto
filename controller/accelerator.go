package controller

import "net"

// 单边模式：加速器已移除，这里仅保留兼容接口。

// InitAccelerator 为 no-op。
func InitAccelerator() {}

// DialAccelerated 退化为快速直连拨号，并返回 used=false。
func DialAccelerated(addr string) (net.Conn, bool, error) {
	c, err := DialFast(addr)
	return c, false, err
}
