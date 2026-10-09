package controller

import (
	"context"
	"errors"
	"moto/utils"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// One immutable identity per successful physical dial. It outlives removal of
// the pool slot and cannot accidentally attribute a late close to its successor.
type http3ConnectionCloseObservation struct {
	once          sync.Once
	generation    uint64
	establishedAt time.Time
	logger        *zap.Logger
}

type http3ConnectionCloseClass struct {
	reason  string
	origin  string
	code    uint64
	hasCode bool
	normal  bool
}

// Never return peer-supplied reason text, server names, reset tokens or frame
// contents. Local/remote denotes the error initiator, not who caused the fault.
func classifyHTTP3ConnectionClose(err error, localRequested bool) http3ConnectionCloseClass {
	var handshake *quic.HandshakeTimeoutError
	var idle *quic.IdleTimeoutError
	var reset *quic.StatelessResetError
	var app *quic.ApplicationError
	var transport *quic.TransportError
	var version *quic.VersionNegotiationError
	switch {
	case errors.As(err, &handshake):
		return http3ConnectionCloseClass{reason: "handshake_timeout", origin: "unknown"}
	case errors.As(err, &idle):
		return http3ConnectionCloseClass{reason: "idle_timeout", origin: "unknown"}
	case errors.As(err, &reset):
		return http3ConnectionCloseClass{reason: "stateless_reset", origin: "remote"}
	case errors.As(err, &app):
		reason, origin := "local_application_close", "local"
		if app.Remote {
			reason, origin = "remote_application_close", "remote"
		} else if localRequested && app.ErrorCode == 0 {
			reason = "local_close"
		}
		return http3ConnectionCloseClass{reason: reason, origin: origin, code: uint64(app.ErrorCode), hasCode: true,
			normal: app.ErrorCode == 0 || app.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError)}
	case errors.As(err, &transport):
		reason, origin := "local_transport_error", "local"
		if transport.Remote {
			reason, origin = "remote_transport_error", "remote"
		}
		return http3ConnectionCloseClass{reason: reason, origin: origin, code: uint64(transport.ErrorCode), hasCode: true,
			normal: transport.ErrorCode == quic.NoError}
	case errors.As(err, &version):
		return http3ConnectionCloseClass{reason: "version_negotiation_error", origin: "unknown"}
	case localRequested && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)):
		return http3ConnectionCloseClass{reason: "local_close", origin: "local", normal: true}
	case errors.Is(err, context.Canceled):
		return http3ConnectionCloseClass{reason: "canceled", origin: "local", normal: true}
	default:
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return http3ConnectionCloseClass{reason: "network_timeout", origin: "unknown"}
		}
		if err != nil {
			return http3ConnectionCloseClass{reason: "network_error", origin: "unknown"}
		}
		return http3ConnectionCloseClass{reason: "unknown", origin: "unknown"}
	}
}

type http3ConnectionCloseMetricKey struct {
	target string
	reason string
}

type http3ConnectionCloseGauge struct {
	target string
	reason string
	count  uint64
}

func (manager *http3ConnectManager) recordHTTP3ConnectionClose(
	key http3ConnectTransportKey, slot *http3ConnectTransportSlot,
	observation *http3ConnectionCloseObservation, cause error,
) {
	if manager == nil || slot == nil || observation == nil {
		return
	}
	observation.once.Do(func() {
		classification := classifyHTTP3ConnectionClose(cause, slot.closeRequested.Load())
		age := max(time.Duration(0), manager.timeNow().Sub(observation.establishedAt))
		manager.mu.Lock()
		active := 0
		for tunnel := range slot.tunnels {
			if tunnel != nil && !tunnel.closed.Load() && tunnel.probation.generationID == observation.generation {
				active++
			}
		}
		if manager.closeEvents == nil {
			manager.closeEvents = make(map[http3ConnectionCloseMetricKey]uint64)
		}
		manager.closeEvents[http3ConnectionCloseMetricKey{target: key.address, reason: classification.reason}]++
		manager.mu.Unlock()
		fields := []zap.Field{
			zap.String("event", "h3_connection_closed"), zap.String("targetAddr", key.address),
			zap.Uint64("generation", observation.generation), zap.String("closeClass", classification.reason),
			zap.String("closeOrigin", classification.origin), zap.Int64("connectionAgeMs", age.Milliseconds()),
			// This is the observation-time count, not an exact failed-request count:
			// a stream may already have handled the close before this callback runs.
			zap.Int("activeTunnelsAtObservation", active),
		}
		if classification.hasCode {
			fields = append(fields, zap.Uint64("closeCode", classification.code))
		}
		level := zapcore.WarnLevel
		if classification.reason == "local_close" || classification.reason == "canceled" ||
			active == 0 && (classification.normal || classification.reason == "idle_timeout") {
			level = zapcore.DebugLevel
		}
		logger := observation.logger
		if logger == nil {
			logger = utils.Logger
		}
		logger.Log(level, "HTTP/3 物理连接已结束", fields...)
	})
}

func renderHTTP3CloseMetrics(output *strings.Builder, events []http3ConnectionCloseGauge) {
	writeMetricHeader(output, "moto_connect_proxy_h3_connection_closes_total",
		"Observed physical HTTP/3 connection closures in the current routing generation by fixed reason class, not failed streams.", "counter")
	for _, event := range events {
		writeMetricSample(output, "moto_connect_proxy_h3_connection_closes_total",
			[]prometheusLabel{{"target", event.target}, {"reason", event.reason}}, strconv.FormatUint(event.count, 10))
	}
}

func sortHTTP3CloseMetrics(events []http3ConnectionCloseGauge) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].target != events[j].target {
			return events[i].target < events[j].target
		}
		return events[i].reason < events[j].reason
	})
}
