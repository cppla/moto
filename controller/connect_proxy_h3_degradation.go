package controller

import (
	"time"

	"github.com/quic-go/quic-go"
)

const (
	http3DegradationSampleInterval = 2 * time.Second
	http3DegradationWindow         = 12 * time.Second
	http3DegradationWarmup         = 15 * time.Second

	http3DegradationMinPackets = uint64(256)
	http3DegradationMinBytes   = uint64(512 << 10)

	http3DegradationRTTFactorNumerator   = int64(5)
	http3DegradationRTTFactorDenominator = int64(2)
	http3DegradationRTTAdditive          = 100 * time.Millisecond
	http3DegradationRTTFloor             = 300 * time.Millisecond

	http3DegradationSoftLossRate   = 0.05
	http3DegradationSevereLossRate = 0.15
	http3DegradationLowThroughput  = 0.20
	http3DegradationWireEfficiency = 0.20

	http3DegradationSingleWriteBlock = 8 * time.Second
	http3DegradationMultiWriteBlock  = 4 * time.Second

	http3DegradationRequiredSignals = 2
	http3DegradationRequiredWindows = 3
)

type http3DegradationReason string

const (
	http3DegradationReasonNone               http3DegradationReason = ""
	http3DegradationReasonConnectionError    http3DegradationReason = "connection_error"
	http3DegradationReasonSevereLossAndWrite http3DegradationReason = "severe_loss_and_blocked_write"
	http3DegradationReasonSustainedSignals   http3DegradationReason = "sustained_signals"
)

// http3DegradationSample is one caller-driven observation of a physical QUIC
// connection. PayloadBytes is a monotonically increasing count of successfully
// relayed application payload in both directions. BlockedWrites is the number
// still pending at the sampling instant. PeakBlockedWrites is diagnostic only;
// it must not turn a fast, already-completed Write into sustained demand.
//
// The detector owns no goroutine. A transport slot calls observe approximately
// every http3DegradationSampleInterval with conn.ConnectionStats().
type http3DegradationSample struct {
	At                    time.Time
	Stats                 quic.ConnectionStats
	PayloadBytes          uint64
	BlockedWrites         int
	PeakBlockedWrites     int
	LongBlockedWrites     int
	OldestBlockedFor      time.Duration
	LastPayloadProgressAt time.Time
	HistoricalBaselineRTT time.Duration
	ConnectionErr         error
}

type http3DegradationSignals struct {
	Sampled          bool
	Warmup           bool
	EnoughTraffic    bool
	LossCounterReset bool

	BaselineRTT  time.Duration
	SmoothedRTT  time.Duration
	RTTThreshold time.Duration
	RTTBad       bool

	LossRate   float64
	LossBad    bool
	SevereLoss bool

	PayloadDemand   bool
	PayloadStalled  bool
	BlockedWrite    bool
	ClearWriteBlock bool
	ThroughputLow   bool
	WireWaste       bool

	BlockedWrites         int
	PeakBlockedWrites     int
	OldestBlockedFor      time.Duration
	LastProgressFor       time.Duration
	PayloadBytesPerSecond float64
	HealthyBytesPerSecond float64

	BadSignalCount     int
	ConsecutiveWindows int
}

type http3DegradationDecision struct {
	Rotate  bool
	Reason  http3DegradationReason
	Signals http3DegradationSignals
}

type http3DegradationWindowDelta struct {
	at time.Time

	bytesSent       uint64
	packetsSent     uint64
	bytesReceived   uint64
	packetsReceived uint64
	bytesLost       uint64
	packetsLost     uint64
	payloadBytes    uint64
}

// http3DegradationDetector is scoped to exactly one physical *quic.Conn. A new
// connection must get a new detector so cumulative counters and the path RTT
// baseline never leak between transports. Its owner must serialize observe
// calls; the intended sampling loop has exactly one caller.
type http3DegradationDetector struct {
	establishedAt time.Time
	baselineRTT   time.Duration

	initialized bool
	lastAt      time.Time
	lastStats   quic.ConnectionStats
	lastPayload uint64

	window                []http3DegradationWindowDelta
	consecutiveBadWindows int
	healthyPayloadRate    float64
	latched               http3DegradationDecision
}

func newHTTP3DegradationDetector(establishedAt time.Time) *http3DegradationDetector {
	return &http3DegradationDetector{establishedAt: establishedAt}
}

func (detector *http3DegradationDetector) observe(sample http3DegradationSample) http3DegradationDecision {
	if detector == nil {
		return http3DegradationDecision{}
	}
	if sample.ConnectionErr != nil {
		if !detector.latched.Rotate {
			detector.latched = http3DegradationDecision{
				Rotate: true,
				Reason: http3DegradationReasonConnectionError,
			}
		}
		return detector.latched
	}

	if sample.At.IsZero() {
		if detector.latched.Rotate {
			return detector.latched
		}
		return http3DegradationDecision{}
	}
	if !detector.initialized {
		detector.initialize(sample)
		return detector.liveDecision(detector.baseSignals(sample, true))
	}
	if !sample.At.After(detector.lastAt) || sample.At.Sub(detector.lastAt) < http3DegradationSampleInterval {
		return detector.liveDecision(detector.baseSignals(sample, false))
	}

	detector.updateBaseline(sample.Stats, sample.HistoricalBaselineRTT)
	signals := detector.baseSignals(sample, true)
	if countersMovedBackward(sample, detector.lastStats, detector.lastPayload) {
		lossReset := sample.Stats.BytesLost < detector.lastStats.BytesLost ||
			sample.Stats.PacketsLost < detector.lastStats.PacketsLost
		detector.resetWindow(sample)
		signals.LossCounterReset = lossReset
		signals.ConsecutiveWindows = 0
		return detector.liveDecision(signals)
	}

	delta := http3DegradationWindowDelta{
		at:              sample.At,
		bytesSent:       sample.Stats.BytesSent - detector.lastStats.BytesSent,
		packetsSent:     sample.Stats.PacketsSent - detector.lastStats.PacketsSent,
		bytesReceived:   sample.Stats.BytesReceived - detector.lastStats.BytesReceived,
		packetsReceived: sample.Stats.PacketsReceived - detector.lastStats.PacketsReceived,
		bytesLost:       sample.Stats.BytesLost - detector.lastStats.BytesLost,
		packetsLost:     sample.Stats.PacketsLost - detector.lastStats.PacketsLost,
		payloadBytes:    sample.PayloadBytes - detector.lastPayload,
	}
	detector.lastAt = sample.At
	detector.lastStats = sample.Stats
	detector.lastPayload = sample.PayloadBytes
	detector.window = append(detector.window, delta)
	detector.trimWindow(sample.At)

	window := sumHTTP3DegradationWindow(detector.window)
	wireBytes := saturatingAdd(window.bytesSent, window.bytesReceived)
	signals.EnoughTraffic = window.packetsSent >= http3DegradationMinPackets || window.bytesSent >= http3DegradationMinBytes
	signals.BlockedWrite = sample.BlockedWrites > 0
	signals.BlockedWrites = sample.BlockedWrites
	signals.PeakBlockedWrites = max(sample.BlockedWrites, sample.PeakBlockedWrites)
	signals.OldestBlockedFor = sample.OldestBlockedFor
	if !sample.LastPayloadProgressAt.IsZero() && !sample.LastPayloadProgressAt.After(sample.At) {
		signals.LastProgressFor = sample.At.Sub(sample.LastPayloadProgressAt)
	}
	signals.PayloadDemand = signals.BlockedWrite
	signals.LossRate = http3DegradationLossRate(window)
	// The minimum outbound sample gate applies only to loss. RTT and explicit
	// application stalls remain useful on low-volume interactive connections.
	if signals.EnoughTraffic {
		signals.LossBad = signals.LossRate > http3DegradationSoftLossRate
		signals.SevereLoss = signals.LossRate > http3DegradationSevereLossRate
	}
	signals.RTTBad = signals.RTTThreshold > 0 && signals.SmoothedRTT > signals.RTTThreshold
	signals.PayloadBytesPerSecond = http3DegradationPayloadRate(detector.window)
	signals.HealthyBytesPerSecond = detector.healthyPayloadRate
	if signals.PayloadDemand && detector.healthyPayloadRate > 0 && signals.OldestBlockedFor >= http3DegradationMultiWriteBlock {
		signals.ThroughputLow = signals.PayloadBytesPerSecond < detector.healthyPayloadRate*http3DegradationLowThroughput
	}
	if signals.PayloadDemand && wireBytes >= http3DegradationMinBytes && signals.OldestBlockedFor >= http3DegradationMultiWriteBlock {
		signals.WireWaste = float64(window.payloadBytes) < float64(wireBytes)*http3DegradationWireEfficiency
	}
	explicitBlock := sample.LongBlockedWrites >= 2 ||
		signals.BlockedWrites >= 1 && signals.OldestBlockedFor >= http3DegradationSingleWriteBlock
	progressStalled := sample.LongBlockedWrites >= 2 && signals.LastProgressFor >= http3DegradationMultiWriteBlock ||
		signals.BlockedWrites >= 1 && signals.LastProgressFor >= http3DegradationSingleWriteBlock
	signals.ClearWriteBlock = explicitBlock || progressStalled
	signals.PayloadStalled = signals.PayloadDemand && (signals.ClearWriteBlock || signals.ThroughputLow || signals.WireWaste)

	// Learn an application-throughput baseline only from busy, unblocked and
	// otherwise healthy intervals. An idle connection therefore never teaches a
	// zero baseline, and a degraded burst cannot poison later comparisons.
	if !signals.Warmup && !signals.BlockedWrite && !signals.RTTBad && !signals.LossBad && signals.PayloadBytesPerSecond > 0 {
		if detector.healthyPayloadRate == 0 {
			detector.healthyPayloadRate = signals.PayloadBytesPerSecond
		} else {
			detector.healthyPayloadRate = detector.healthyPayloadRate*0.8 + signals.PayloadBytesPerSecond*0.2
		}
		signals.HealthyBytesPerSecond = detector.healthyPayloadRate
	}

	if signals.RTTBad {
		signals.BadSignalCount++
	}
	if signals.LossBad {
		signals.BadSignalCount++
	}
	if signals.PayloadStalled {
		signals.BadSignalCount++
	}

	if signals.Warmup {
		detector.consecutiveBadWindows = 0
		signals.ConsecutiveWindows = 0
		return detector.liveDecision(signals)
	}

	if detector.latched.Rotate {
		return detector.liveDecision(signals)
	}

	if signals.SevereLoss && signals.ClearWriteBlock {
		signals.ConsecutiveWindows = detector.consecutiveBadWindows
		detector.latched = http3DegradationDecision{
			Rotate:  true,
			Reason:  http3DegradationReasonSevereLossAndWrite,
			Signals: signals,
		}
		return detector.latched
	}

	if signals.BadSignalCount >= http3DegradationRequiredSignals {
		detector.consecutiveBadWindows++
	} else {
		detector.consecutiveBadWindows = 0
	}
	signals.ConsecutiveWindows = detector.consecutiveBadWindows
	if detector.consecutiveBadWindows >= http3DegradationRequiredWindows {
		detector.latched = http3DegradationDecision{
			Rotate:  true,
			Reason:  http3DegradationReasonSustainedSignals,
			Signals: signals,
		}
		return detector.latched
	}
	return http3DegradationDecision{Signals: signals}
}

func (detector *http3DegradationDetector) liveDecision(signals http3DegradationSignals) http3DegradationDecision {
	if detector != nil && detector.latched.Rotate {
		return http3DegradationDecision{Rotate: true, Reason: detector.latched.Reason, Signals: signals}
	}
	return http3DegradationDecision{Signals: signals}
}

func (detector *http3DegradationDetector) initialize(sample http3DegradationSample) {
	detector.initialized = true
	detector.lastAt = sample.At
	detector.lastStats = sample.Stats
	detector.lastPayload = sample.PayloadBytes
	if detector.establishedAt.IsZero() {
		detector.establishedAt = sample.At
	}
	detector.updateBaseline(sample.Stats, sample.HistoricalBaselineRTT)
}

func (detector *http3DegradationDetector) resetWindow(sample http3DegradationSample) {
	detector.window = detector.window[:0]
	detector.consecutiveBadWindows = 0
	detector.lastAt = sample.At
	detector.lastStats = sample.Stats
	detector.lastPayload = sample.PayloadBytes
	detector.updateBaseline(sample.Stats, sample.HistoricalBaselineRTT)
}

func (detector *http3DegradationDetector) baseSignals(sample http3DegradationSample, sampled bool) http3DegradationSignals {
	warmup := sample.At.Before(detector.establishedAt.Add(http3DegradationWarmup))
	return http3DegradationSignals{
		Sampled:      sampled,
		Warmup:       warmup,
		BaselineRTT:  detector.baselineRTT,
		SmoothedRTT:  sample.Stats.SmoothedRTT,
		RTTThreshold: http3DegradationRTTThreshold(detector.baselineRTT),
	}
}

func (detector *http3DegradationDetector) updateBaseline(stats quic.ConnectionStats, historical time.Duration) {
	candidate := stats.MinRTT
	if candidate <= 0 {
		candidate = stats.SmoothedRTT
	}
	if candidate > 0 && (detector.baselineRTT <= 0 || candidate < detector.baselineRTT) {
		detector.baselineRTT = candidate
	}
	if historical > 0 && (detector.baselineRTT <= 0 || historical < detector.baselineRTT) {
		detector.baselineRTT = historical
	}
}

func (detector *http3DegradationDetector) trimWindow(now time.Time) {
	cutoff := now.Add(-http3DegradationWindow)
	first := 0
	for first < len(detector.window) && !detector.window[first].at.After(cutoff) {
		first++
	}
	if first == 0 {
		return
	}
	copy(detector.window, detector.window[first:])
	clear(detector.window[len(detector.window)-first:])
	detector.window = detector.window[:len(detector.window)-first]
}

func sumHTTP3DegradationWindow(window []http3DegradationWindowDelta) http3DegradationWindowDelta {
	var sum http3DegradationWindowDelta
	for _, delta := range window {
		sum.bytesSent = saturatingAdd(sum.bytesSent, delta.bytesSent)
		sum.packetsSent = saturatingAdd(sum.packetsSent, delta.packetsSent)
		sum.bytesReceived = saturatingAdd(sum.bytesReceived, delta.bytesReceived)
		sum.packetsReceived = saturatingAdd(sum.packetsReceived, delta.packetsReceived)
		sum.bytesLost = saturatingAdd(sum.bytesLost, delta.bytesLost)
		sum.packetsLost = saturatingAdd(sum.packetsLost, delta.packetsLost)
		sum.payloadBytes = saturatingAdd(sum.payloadBytes, delta.payloadBytes)
	}
	return sum
}

func http3DegradationPayloadRate(window []http3DegradationWindowDelta) float64 {
	if len(window) == 0 {
		return 0
	}
	bytes := sumHTTP3DegradationWindow(window).payloadBytes
	duration := http3DegradationSampleInterval
	if len(window) > 1 {
		duration = window[len(window)-1].at.Sub(window[0].at) + http3DegradationSampleInterval
	}
	if duration <= 0 {
		return 0
	}
	return float64(bytes) / duration.Seconds()
}

func http3DegradationLossRate(window http3DegradationWindowDelta) float64 {
	var packetRate, byteRate float64
	if window.packetsSent > 0 {
		packetRate = float64(window.packetsLost) / float64(window.packetsSent)
	}
	if window.bytesSent > 0 {
		byteRate = float64(window.bytesLost) / float64(window.bytesSent)
	}
	rate := max(packetRate, byteRate)
	return min(rate, 1)
}

func http3DegradationRTTThreshold(baseline time.Duration) time.Duration {
	if baseline <= 0 {
		return 0
	}
	factor := baseline * time.Duration(http3DegradationRTTFactorNumerator) /
		time.Duration(http3DegradationRTTFactorDenominator)
	return max(factor, baseline+http3DegradationRTTAdditive, http3DegradationRTTFloor)
}

func countersMovedBackward(sample http3DegradationSample, previous quic.ConnectionStats, previousPayload uint64) bool {
	return sample.Stats.BytesSent < previous.BytesSent ||
		sample.Stats.PacketsSent < previous.PacketsSent ||
		sample.Stats.BytesReceived < previous.BytesReceived ||
		sample.Stats.PacketsReceived < previous.PacketsReceived ||
		sample.Stats.BytesLost < previous.BytesLost ||
		sample.Stats.PacketsLost < previous.PacketsLost ||
		sample.PayloadBytes < previousPayload
}

func saturatingAdd(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}
