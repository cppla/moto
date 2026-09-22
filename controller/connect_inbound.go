package controller

import "net"

// Both CONNECT frontends acknowledge only the final winning upstream tunnel.
// Keeping replies outside target dialing avoids writing multiple responses
// during hedging, fallback, or a retry against a different target.
func markConnectClientConnected(conn net.Conn) error {
	if client, ok := conn.(*httpConnectClientConn); ok {
		return client.replyConnected()
	}
	return markSOCKS5Connected(conn)
}

func failPendingConnectClient(conn net.Conn) {
	if client, ok := conn.(*httpConnectClientConn); ok {
		client.replyFailure()
		return
	}
	failPendingSOCKS5(conn)
}

func setPendingConnectClientFailure(conn net.Conn, err error) {
	if client, ok := conn.(*httpConnectClientConn); ok {
		if !client.replied {
			client.failureStatus = connectProxyHTTPReply(err)
		}
		return
	}
	setPendingSOCKS5Failure(conn, err)
}
