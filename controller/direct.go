package controller

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DialFast performs fastest direct TCP dial by resolving all IPs for host
// and attempting parallel connections, returning the first success.
func DialFast(addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		target := net.JoinHostPort(ip.String(), port)
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, rerr := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if rerr != nil || len(addrs) == 0 {
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
	}
	type result struct {
		c   net.Conn
		err error
	}
	resCh := make(chan result, 1)
	for i, ip := range addrs {
		go func(delay int, ip net.IP) {
			if delay > 0 {
				select {
				case <-time.After(time.Duration(delay) * 50 * time.Millisecond):
				case <-ctx.Done():
					return
				}
			}
			d := &net.Dialer{Timeout: 2 * time.Second}
			c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				select {
				case resCh <- result{c: c}:
					cancel()
				default:
					_ = c.Close()
				}
			}
		}(i, ip)
	}
	select {
	case r := <-resCh:
		return r.c, r.err
	case <-ctx.Done():
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
	}
}
