package controller

import (
	"context"

	"github.com/quic-go/quic-go"
)

// ownPhysicalConnection covers connections removed from http3.Transport's
// client cache after a stream-level RoundTrip error. With a custom Dial,
// Transport.Close cannot close those connections. Do not close a superseded
// connection here: it may still carry established sibling CONNECT streams.
// physicalMu is never held while entering the manager or quic-go.
func (slot *http3ConnectTransportSlot) ownPhysicalConnection(connection *quic.Conn) bool {
	if slot == nil || connection == nil {
		return false
	}
	slot.physicalMu.Lock()
	if slot.closeRequested.Load() {
		slot.physicalMu.Unlock()
		_ = connection.CloseWithError(0, "")
		return false
	}
	if slot.physicalConns == nil {
		slot.physicalConns = make(map[*quic.Conn]struct{})
	}
	_, alreadyOwned := slot.physicalConns[connection]
	slot.physicalConns[connection] = struct{}{}
	slot.physicalMu.Unlock()
	if !alreadyOwned {
		context.AfterFunc(connection.Context(), func() {
			slot.physicalMu.Lock()
			delete(slot.physicalConns, connection)
			slot.physicalMu.Unlock()
		})
	}
	return true
}

func (slot *http3ConnectTransportSlot) closePhysicalConnections() {
	slot.physicalMu.Lock()
	connections := make([]*quic.Conn, 0, len(slot.physicalConns))
	for connection := range slot.physicalConns {
		connections = append(connections, connection)
	}
	clear(slot.physicalConns)
	slot.physicalMu.Unlock()
	for _, connection := range connections {
		// Match http3.Transport.Close's code and existing local-close metrics.
		_ = connection.CloseWithError(0, "")
	}
}

func (slot *http3ConnectTransportSlot) hasMultiplePhysicalConnections() bool {
	slot.physicalMu.Lock()
	defer slot.physicalMu.Unlock()
	alive := 0
	for connection := range slot.physicalConns {
		if connection.Context().Err() == nil {
			alive++
			if alive > 1 {
				return true
			}
		}
	}
	return false
}

// A non-canceled RoundTrip error can evict quic-go's cached client without
// closing its physical QUIC connection. Stop assigning new requests to that
// slot and let existing users drain; releaseTransport closes every owned
// connection after the last user leaves. This is local pool retirement, not a
// degradation signal or permission to abort established sibling streams.
// Warming candidates retain their existing failure/backoff/link handling.
func (manager *http3ConnectManager) drainHTTP3ErroredTransport(key http3ConnectTransportKey, slot *http3ConnectTransportSlot) {
	manager.mu.Lock()
	if manager.containsSlotLocked(key, slot) && slot.lifecycle == http3TransportServing {
		slot.lifecycle = http3TransportDraining
	}
	manager.mu.Unlock()
}
