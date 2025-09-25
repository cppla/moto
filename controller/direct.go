package controller

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// dialConn 在原始连接基础上附带拨号延迟，供自适应复制逻辑使用。
type dialConn struct {
	net.Conn
	latency time.Duration
}

func (d *dialConn) DialLatency() time.Duration { return d.latency }

// DialFast 实现简化版的 Happy Eyeballs，并记录拨号延迟。
func DialFast(addr string) (net.Conn, error) {
	start := time.Now()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
		if e != nil {
			return nil, e
		}
		return &dialConn{Conn: c, latency: time.Since(start)}, nil
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		target := net.JoinHostPort(ip.String(), port)
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", target)
		if e != nil {
			return nil, e
		}
		return &dialConn{Conn: c, latency: time.Since(start)}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, rerr := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if rerr != nil || len(addrs) == 0 {
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
		if e != nil {
			return nil, e
		}
		return &dialConn{Conn: c, latency: time.Since(start)}, nil
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
		if r.err != nil {
			return nil, r.err
		}
		return &dialConn{Conn: r.c, latency: time.Since(start)}, nil
	case <-ctx.Done():
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
		if e != nil {
			return nil, e
		}
		return &dialConn{Conn: c, latency: time.Since(start)}, nil
	}
}
