package controller

import (
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestHTTP3DegradationThresholds(t *testing.T) {
	tests := []struct {
		name     string
		baseline time.Duration
		want     time.Duration
	}{
		{name: "floor wins", baseline: 50 * time.Millisecond, want: 300 * time.Millisecond},
		{name: "factor wins", baseline: 200 * time.Millisecond, want: 500 * time.Millisecond},
		{name: "zero has no threshold", baseline: 0, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := http3DegradationRTTThreshold(test.baseline); got != test.want {
				t.Fatalf("RTT threshold = %s, want %s", got, test.want)
			}
		})
	}
}

func TestHTTP3DegradationConnectionErrorIsImmediate(t *testing.T) {
	detector := newHTTP3DegradationDetector(time.Time{})
	wantErr := errors.New("QUIC connection closed")
	decision := detector.observe(http3DegradationSample{ConnectionErr: wantErr})
	if !decision.Rotate || decision.Reason != http3DegradationReasonConnectionError {
		t.Fatalf("decision = %+v, want immediate connection-error rotation", decision)
	}
	if repeated := detector.observe(http3DegradationSample{}); repeated != decision {
		t.Fatalf("latched decision = %+v, want %+v", repeated, decision)
	}
}

func TestHTTP3DegradationWarmupAndTrafficGate(t *testing.T) {
	start := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start)
	stats := quic.ConnectionStats{MinRTT: 100 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	for index := 1; index <= 7; index++ {
		stats.PacketsSent += 100
		stats.BytesSent += 200 << 10
		stats.PacketsLost += 10
		stats.BytesLost += 20 << 10
		decision := detector.observe(http3DegradationSample{
			At:            start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:         stats,
			BlockedWrites: 1,
		})
		if decision.Rotate {
			t.Fatalf("warmup sample %d rotated: %+v", index, decision)
		}
		if !decision.Signals.Warmup {
			t.Fatalf("sample %d did not report warmup", index)
		}
	}

	// Warmup has elapsed, but a fresh detector with too little traffic must not
	// accumulate bad windows.
	lowTraffic := newHTTP3DegradationDetector(start)
	stats = quic.ConnectionStats{MinRTT: 100 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	lowTraffic.observe(http3DegradationSample{At: start, Stats: stats})
	for index := 1; index <= 12; index++ {
		stats.PacketsSent++
		stats.BytesSent += 1024
		stats.PacketsLost++
		stats.BytesLost += 1024
		decision := lowTraffic.observe(http3DegradationSample{
			At:            start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:         stats,
			BlockedWrites: 1,
		})
		if decision.Rotate || decision.Signals.EnoughTraffic {
			t.Fatalf("low-traffic sample %d = %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationRequiresThreeConsecutiveTwoOfThreeWindows(t *testing.T) {
	start := time.Date(2026, 8, 26, 12, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start)
	stats := quic.ConnectionStats{MinRTT: 100 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	var decision http3DegradationDecision
	for index := 1; index <= 10; index++ {
		stats.PacketsSent += 100
		stats.BytesSent += 200 << 10
		decision = detector.observe(http3DegradationSample{
			At:               start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:            stats,
			BlockedWrites:    1,
			OldestBlockedFor: http3DegradationSingleWriteBlock,
		})
		if index < 10 && decision.Rotate {
			t.Fatalf("sample %d rotated before three eligible windows: %+v", index, decision)
		}
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonSustainedSignals {
		t.Fatalf("decision = %+v, want sustained-signal rotation", decision)
	}
	if decision.Signals.BadSignalCount != 2 || decision.Signals.ConsecutiveWindows != 3 {
		t.Fatalf("signals = %+v, want two signals for three windows", decision.Signals)
	}
}

func TestHTTP3DegradationSevereLossAndBlockedWriteTriggersFast(t *testing.T) {
	start := time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start)
	stats := quic.ConnectionStats{MinRTT: 100 * time.Millisecond, SmoothedRTT: 100 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	var decision http3DegradationDecision
	for index := 1; index <= 8; index++ {
		stats.PacketsSent += 100
		stats.BytesSent += 200 << 10
		stats.PacketsLost += 16
		stats.BytesLost += 32 << 10
		decision = detector.observe(http3DegradationSample{
			At:               start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:            stats,
			BlockedWrites:    1,
			OldestBlockedFor: http3DegradationSingleWriteBlock,
		})
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonSevereLossAndWrite {
		t.Fatalf("decision = %+v, want severe-loss fast rotation", decision)
	}
	if decision.Signals.LossRate <= http3DegradationSevereLossRate {
		t.Fatalf("loss rate = %f, want > %f", decision.Signals.LossRate, http3DegradationSevereLossRate)
	}
}

func TestHTTP3DegradationSevereLossWithoutBlockedWriteIsNotFast(t *testing.T) {
	start := time.Date(2026, 8, 26, 13, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start)
	stats := quic.ConnectionStats{MinRTT: 100 * time.Millisecond, SmoothedRTT: 100 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	for index := 1; index <= 10; index++ {
		stats.PacketsSent += 100
		stats.BytesSent += 200 << 10
		stats.PacketsLost += 20
		stats.BytesLost += 40 << 10
		decision := detector.observe(http3DegradationSample{
			At:           start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:        stats,
			PayloadBytes: uint64(index) * (64 << 10),
		})
		if decision.Rotate {
			t.Fatalf("sample %d rotated on loss alone: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationLossCounterRollbackResetsWindow(t *testing.T) {
	start := time.Date(2026, 8, 26, 14, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		MinRTT:      100 * time.Millisecond,
		SmoothedRTT: 600 * time.Millisecond,
		BytesLost:   100 << 10,
		PacketsLost: 100,
	}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	for index := 1; index <= 2; index++ {
		stats.PacketsSent += 300
		stats.BytesSent += 600 << 10
		decision := detector.observe(http3DegradationSample{
			At:            start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:         stats,
			BlockedWrites: 1,
		})
		if decision.Rotate {
			t.Fatalf("pre-reset sample %d rotated: %+v", index, decision)
		}
	}

	stats.PacketsSent += 300
	stats.BytesSent += 600 << 10
	stats.PacketsLost = 50
	stats.BytesLost = 50 << 10
	decision := detector.observe(http3DegradationSample{
		At:            start.Add(3 * http3DegradationSampleInterval),
		Stats:         stats,
		BlockedWrites: 1,
	})
	if decision.Rotate || !decision.Signals.LossCounterReset {
		t.Fatalf("rollback decision = %+v, want a non-rotating reset", decision)
	}
	if decision.Signals.ConsecutiveWindows != 0 || len(detector.window) != 0 {
		t.Fatalf("rollback retained state: decision=%+v window=%d", decision, len(detector.window))
	}

	stats.PacketsSent += 300
	stats.BytesSent += 600 << 10
	decision = detector.observe(http3DegradationSample{
		At:            start.Add(4 * http3DegradationSampleInterval),
		Stats:         stats,
		BlockedWrites: 1,
	})
	if decision.Signals.LossRate != 0 || decision.Signals.LossBad {
		t.Fatalf("post-reset loss signals = %+v, want a clean baseline", decision.Signals)
	}
}

func TestHTTP3DegradationIgnoresSamplesFasterThanTwoSeconds(t *testing.T) {
	start := time.Date(2026, 8, 26, 14, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start)
	stats := quic.ConnectionStats{MinRTT: 100 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})
	stats.PacketsSent = 1000
	stats.BytesSent = 1 << 20
	decision := detector.observe(http3DegradationSample{
		At:            start.Add(time.Second),
		Stats:         stats,
		BlockedWrites: 1,
	})
	if decision.Signals.Sampled || len(detector.window) != 0 {
		t.Fatalf("early sample was accepted: decision=%+v window=%d", decision, len(detector.window))
	}
}

func TestHTTP3DegradationDoesNotRotateByConnectionAge(t *testing.T) {
	now := time.Date(2026, 8, 26, 15, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(now.Add(-30 * 24 * time.Hour))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 90 * time.Millisecond}
	detector.observe(http3DegradationSample{At: now, Stats: stats})

	for index := 1; index <= 10; index++ {
		stats.PacketsReceived += 300
		stats.BytesReceived += 1 << 20
		decision := detector.observe(http3DegradationSample{
			At:           now.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:        stats,
			PayloadBytes: uint64(index) << 20,
		})
		if decision.Rotate {
			t.Fatalf("healthy 30-day-old connection rotated at sample %d: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationUsesHistoricalRTTBaseline(t *testing.T) {
	start := time.Date(2026, 8, 26, 15, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 250 * time.Millisecond, SmoothedRTT: 350 * time.Millisecond}
	detector.observe(http3DegradationSample{
		At:                    start,
		Stats:                 stats,
		HistoricalBaselineRTT: 80 * time.Millisecond,
	})
	stats.PacketsReceived = http3DegradationMinPackets
	decision := detector.observe(http3DegradationSample{
		At:                    start.Add(http3DegradationSampleInterval),
		Stats:                 stats,
		HistoricalBaselineRTT: 80 * time.Millisecond,
	})
	if decision.Signals.BaselineRTT != 80*time.Millisecond {
		t.Fatalf("baseline RTT = %s, want historical 80ms", decision.Signals.BaselineRTT)
	}
	if decision.Signals.RTTThreshold != http3DegradationRTTFloor {
		t.Fatalf("RTT threshold = %s, want %s", decision.Signals.RTTThreshold, http3DegradationRTTFloor)
	}
	if !decision.Signals.RTTBad {
		t.Fatalf("historical baseline did not expose RTT inflation: %+v", decision.Signals)
	}
}

func TestHTTP3DegradationBlockedWriteDurations(t *testing.T) {
	tests := []struct {
		name          string
		blockedWrites int
		before        time.Duration
		threshold     time.Duration
	}{
		{
			name:          "one write requires eight seconds",
			blockedWrites: 1,
			before:        http3DegradationSingleWriteBlock - time.Nanosecond,
			threshold:     http3DegradationSingleWriteBlock,
		},
		{
			name:          "two writes require four seconds",
			blockedWrites: 2,
			before:        http3DegradationMultiWriteBlock - time.Nanosecond,
			threshold:     http3DegradationMultiWriteBlock,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := time.Date(2026, 8, 26, 16, 0, 0, 0, time.UTC)
			detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
			stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 80 * time.Millisecond}
			detector.observe(http3DegradationSample{At: start, Stats: stats})

			stats.PacketsReceived += http3DegradationMinPackets
			before := detector.observe(http3DegradationSample{
				At:                start.Add(http3DegradationSampleInterval),
				Stats:             stats,
				BlockedWrites:     test.blockedWrites,
				LongBlockedWrites: 0,
				OldestBlockedFor:  test.before,
			})
			if before.Signals.PayloadStalled {
				t.Fatalf("blocked duration %s triggered before %s: %+v", test.before, test.threshold, before.Signals)
			}

			stats.PacketsReceived += http3DegradationMinPackets
			longBlockedWrites := 0
			if test.blockedWrites >= 2 {
				longBlockedWrites = test.blockedWrites
			}
			atThreshold := detector.observe(http3DegradationSample{
				At:                start.Add(2 * http3DegradationSampleInterval),
				Stats:             stats,
				BlockedWrites:     test.blockedWrites,
				LongBlockedWrites: longBlockedWrites,
				OldestBlockedFor:  test.threshold,
			})
			if !atThreshold.Signals.PayloadStalled {
				t.Fatalf("blocked duration %s did not trigger at threshold: %+v", test.threshold, atThreshold.Signals)
			}
			if atThreshold.Rotate {
				t.Fatalf("one payload-stall signal rotated immediately: %+v", atThreshold)
			}
		})
	}
}

func TestHTTP3DegradationDetectsThroughputBelowHealthyBusyBaseline(t *testing.T) {
	start := time.Date(2026, 8, 26, 16, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 80 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	var payload uint64
	for index := 1; index <= 6; index++ {
		stats.PacketsReceived += 1000
		stats.BytesReceived += 1 << 20
		payload += 1 << 20
		decision := detector.observe(http3DegradationSample{
			At:           start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:        stats,
			PayloadBytes: payload,
		})
		if decision.Rotate || decision.Signals.HealthyBytesPerSecond <= 0 {
			t.Fatalf("healthy busy sample %d failed to learn baseline: %+v", index, decision)
		}
	}
	healthyRate := detector.healthyPayloadRate

	var decision http3DegradationDecision
	for index := 7; index <= 12; index++ {
		stats.PacketsReceived += 100
		stats.BytesReceived += 50 << 10
		payload += 50 << 10
		decision = detector.observe(http3DegradationSample{
			At:                    start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:                 stats,
			PayloadBytes:          payload,
			BlockedWrites:         1,
			OldestBlockedFor:      http3DegradationMultiWriteBlock,
			LastPayloadProgressAt: start.Add(time.Duration(index) * http3DegradationSampleInterval),
		})
	}
	if !decision.Signals.ThroughputLow || !decision.Signals.PayloadStalled {
		t.Fatalf("low-throughput phase was not detected: %+v", decision.Signals)
	}
	if decision.Signals.PayloadBytesPerSecond >= healthyRate*http3DegradationLowThroughput {
		t.Fatalf("payload rate %.0f is not below 20%% of healthy %.0f", decision.Signals.PayloadBytesPerSecond, healthyRate)
	}
	if decision.Rotate {
		t.Fatalf("throughput signal alone rotated: %+v", decision)
	}
}

func TestHTTP3DegradationDetectsWireWaste(t *testing.T) {
	start := time.Date(2026, 8, 26, 17, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 80 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	stats.PacketsReceived = 1000
	stats.BytesReceived = 1 << 20
	decision := detector.observe(http3DegradationSample{
		At:               start.Add(http3DegradationSampleInterval),
		Stats:            stats,
		PayloadBytes:     10 << 10,
		BlockedWrites:    1,
		OldestBlockedFor: http3DegradationMultiWriteBlock,
	})
	if !decision.Signals.WireWaste || !decision.Signals.PayloadStalled {
		t.Fatalf("wire-heavy payload-light sample was not detected: %+v", decision.Signals)
	}
	if decision.Rotate || decision.Signals.BadSignalCount != 1 {
		t.Fatalf("wire waste alone must remain one non-rotating signal: %+v", decision)
	}
}

func TestHTTP3DegradationSingleSignalNeverRotates(t *testing.T) {
	start := time.Date(2026, 8, 26, 17, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	for index := 1; index <= 12; index++ {
		stats.PacketsReceived += 300
		stats.BytesReceived += 1 << 20
		decision := detector.observe(http3DegradationSample{
			At:           start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:        stats,
			PayloadBytes: uint64(index) << 20,
		})
		if decision.Rotate || decision.Signals.BadSignalCount != 1 || !decision.Signals.RTTBad {
			t.Fatalf("RTT-only sample %d = %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationIdleConnectionDoesNotFalsePositive(t *testing.T) {
	start := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-24 * time.Hour))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	for index := 1; index <= 30; index++ {
		decision := detector.observe(http3DegradationSample{
			At:    start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats: stats,
		})
		if decision.Rotate || decision.Signals.EnoughTraffic || decision.Signals.PayloadDemand {
			t.Fatalf("idle sample %d false-positive: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationInstantWriteDoesNotSatisfySevereLossFastPath(t *testing.T) {
	start := time.Date(2026, 8, 26, 18, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 80 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	for index := 1; index <= 6; index++ {
		stats.PacketsSent += 300
		stats.BytesSent += 600 << 10
		stats.PacketsLost += 60
		stats.BytesLost += 120 << 10
		decision := detector.observe(http3DegradationSample{
			At:                start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:             stats,
			PeakBlockedWrites: 1,
		})
		if decision.Rotate || decision.Signals.BlockedWrite || decision.Signals.ClearWriteBlock {
			t.Fatalf("instant completed write triggered severe-loss rotation at %d: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationRecoveredWriteDoesNotStickInWindow(t *testing.T) {
	start := time.Date(2026, 8, 26, 19, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	stats.PacketsSent += 300
	stats.BytesSent += 600 << 10
	blocked := detector.observe(http3DegradationSample{
		At:                start.Add(http3DegradationSampleInterval),
		Stats:             stats,
		BlockedWrites:     2,
		LongBlockedWrites: 2,
		OldestBlockedFor:  http3DegradationMultiWriteBlock,
	})
	if blocked.Signals.BadSignalCount != 2 || blocked.Signals.ConsecutiveWindows != 1 {
		t.Fatalf("initial blocked window = %+v", blocked)
	}

	for index := 2; index <= 5; index++ {
		stats.PacketsSent += 300
		stats.BytesSent += 600 << 10
		decision := detector.observe(http3DegradationSample{
			At:    start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats: stats,
		})
		if decision.Rotate || decision.Signals.PayloadDemand || decision.Signals.PayloadStalled ||
			decision.Signals.ConsecutiveWindows != 0 || decision.Signals.BadSignalCount != 1 {
			t.Fatalf("recovered write remained sticky at %d: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationReceiveOnlyTrafficDoesNotSatisfyOutboundSampleGate(t *testing.T) {
	start := time.Date(2026, 8, 26, 19, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})
	stats.PacketsSent = 1
	stats.BytesSent = 1200
	stats.PacketsLost = 1
	stats.BytesLost = 1200
	stats.PacketsReceived = 1000
	stats.BytesReceived = 8 << 20
	decision := detector.observe(http3DegradationSample{
		At:               start.Add(http3DegradationSampleInterval),
		Stats:            stats,
		BlockedWrites:    1,
		OldestBlockedFor: http3DegradationSingleWriteBlock,
	})
	if decision.Signals.EnoughTraffic || decision.Signals.LossBad || decision.Signals.SevereLoss || decision.Rotate {
		t.Fatalf("receive-only traffic passed outbound sample gate: %+v", decision)
	}
}

func TestHTTP3DegradationLowTrafficStillUsesRTTAndApplicationSignals(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 600 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	var decision http3DegradationDecision
	for index := 1; index <= http3DegradationRequiredWindows; index++ {
		stats.PacketsSent++
		stats.BytesSent += 1024
		stats.PacketsLost++
		stats.BytesLost += 1024
		decision = detector.observe(http3DegradationSample{
			At:               start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:            stats,
			BlockedWrites:    1,
			OldestBlockedFor: http3DegradationSingleWriteBlock,
		})
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonSustainedSignals {
		t.Fatalf("low-traffic RTT plus application stall did not rotate: %+v", decision)
	}
	if decision.Signals.EnoughTraffic || decision.Signals.LossBad || decision.Signals.BadSignalCount != 2 {
		t.Fatalf("low-traffic signals = %+v, want RTT plus application only", decision.Signals)
	}
}

func TestHTTP3DegradationRequiresTwoIndividuallyLongBlockedWrites(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{MinRTT: 80 * time.Millisecond, SmoothedRTT: 80 * time.Millisecond}
	detector.observe(http3DegradationSample{At: start, Stats: stats})

	oneLong := detector.observe(http3DegradationSample{
		At:                start.Add(http3DegradationSampleInterval),
		Stats:             stats,
		BlockedWrites:     2,
		LongBlockedWrites: 1,
		OldestBlockedFor:  http3DegradationMultiWriteBlock,
	})
	if oneLong.Signals.ClearWriteBlock || oneLong.Signals.PayloadStalled {
		t.Fatalf("one old and one fresh write counted as two long blocks: %+v", oneLong.Signals)
	}

	twoLong := detector.observe(http3DegradationSample{
		At:                start.Add(2 * http3DegradationSampleInterval),
		Stats:             stats,
		BlockedWrites:     2,
		LongBlockedWrites: 2,
		OldestBlockedFor:  http3DegradationMultiWriteBlock,
	})
	if !twoLong.Signals.ClearWriteBlock || !twoLong.Signals.PayloadStalled {
		t.Fatalf("two writes blocked for four seconds were not detected: %+v", twoLong.Signals)
	}
}

func TestHTTP3DegradationDetectsUDPBlackholeAfterRepeatedOutboundProbes(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		MinRTT:          80 * time.Millisecond,
		SmoothedRTT:     80 * time.Millisecond,
		PacketsSent:     20,
		BytesSent:       20 << 10,
		PacketsReceived: 20,
		BytesReceived:   20 << 10,
	}
	detector.observe(http3DegradationSample{At: start, Stats: stats, PayloadBytes: 4096})

	var decision http3DegradationDecision
	for index := 1; index <= 5; index++ {
		// Model PTO backoff: the outbound counters advance in multiple, but not
		// necessarily every, sampler intervals while every receive counter stays
		// completely frozen.
		if index == 1 || index == 3 {
			stats.PacketsSent++
			stats.BytesSent += 1200
		}
		decision = detector.observe(http3DegradationSample{
			At:                    start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:                 stats,
			PayloadBytes:          4096,
			BlockedWrites:         1,
			OldestBlockedFor:      time.Duration(index) * http3DegradationSampleInterval,
			LastPayloadProgressAt: start,
		})
		if index < 5 && decision.Rotate {
			t.Fatalf("blackhole rotated too early at sample %d: %+v", index, decision)
		}
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonUDPBlackhole {
		t.Fatalf("blackhole decision = %+v", decision)
	}
	if !decision.Signals.SentNoReceive || !decision.Signals.UDPBlackhole ||
		decision.Signals.NoReceiveFor < http3UDPBlackholeStallTimeout ||
		decision.Signals.BlackholeWindows != http3UDPBlackholeConfirmations {
		t.Fatalf("blackhole signals = %+v", decision.Signals)
	}
}

func TestHTTP3DegradationDetectsReadOnlyUDPBlackhole(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 10, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		MinRTT:          80 * time.Millisecond,
		SmoothedRTT:     80 * time.Millisecond,
		PacketsSent:     20,
		BytesSent:       20 << 10,
		PacketsReceived: 20,
		BytesReceived:   20 << 10,
	}
	const downloaded = uint64(256 << 10)
	detector.observe(http3DegradationSample{
		At: start, Stats: stats, PayloadBytes: downloaded, PayloadReadBytes: downloaded,
		LastPayloadProgressAt: start,
	})

	var decision http3DegradationDecision
	for index := 1; index <= 5; index++ {
		if index == 1 || index == 3 {
			stats.PacketsSent++
			stats.BytesSent += 1200
		}
		decision = detector.observe(http3DegradationSample{
			At:                    start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:                 stats,
			PayloadBytes:          downloaded,
			PayloadReadBytes:      downloaded,
			BlockedReads:          1,
			OldestReadBlockedFor:  time.Duration(index) * http3DegradationSampleInterval,
			RecentReadDemand:      index == 1,
			LastPayloadProgressAt: start,
		})
		if index < 5 && decision.Rotate {
			t.Fatalf("read-only blackhole rotated too early at sample %d: %+v", index, decision)
		}
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonUDPBlackhole {
		t.Fatalf("read-only blackhole decision = %+v", decision)
	}
	if !decision.Signals.ReadDemand || decision.Signals.BlockedWrites != 0 ||
		decision.Signals.BlackholeWindows != http3UDPBlackholeConfirmations {
		t.Fatalf("read-only blackhole signals = %+v", decision.Signals)
	}
}

func TestHTTP3DegradationPendingReadWithoutRecentPayloadIsIdle(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 20, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: 10, BytesReceived: 10 << 10,
	}
	detector.observe(http3DegradationSample{At: start, Stats: stats})
	for index := 1; index <= 8; index++ {
		stats.PacketsSent++
		stats.BytesSent += 1200
		decision := detector.observe(http3DegradationSample{
			At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats,
			BlockedReads: 1, OldestReadBlockedFor: time.Duration(index) * http3DegradationSampleInterval,
			LastPayloadProgressAt: start,
		})
		if decision.Rotate || decision.Signals.ReadDemand || decision.Signals.UDPBlackhole {
			t.Fatalf("idle pending Read false-positive at sample %d: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationReadOnlyBlackholeResetsOnQUICAck(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 25, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: 10, BytesReceived: 10 << 10,
	}
	const downloaded = uint64(128 << 10)
	detector.observe(http3DegradationSample{
		At: start, Stats: stats, PayloadBytes: downloaded, PayloadReadBytes: downloaded,
	})
	for index := 1; index <= 4; index++ {
		if index <= 2 {
			stats.PacketsSent++
			stats.BytesSent += 1200
		}
		decision := detector.observe(http3DegradationSample{
			At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats,
			PayloadBytes: downloaded, PayloadReadBytes: downloaded, BlockedReads: 1,
			OldestReadBlockedFor: time.Duration(index) * http3DegradationSampleInterval,
			RecentReadDemand:     index == 1, LastPayloadProgressAt: start,
		})
		if decision.Rotate {
			t.Fatalf("read-only blackhole rotated before ACK: %+v", decision)
		}
	}
	stats.PacketsReceived++
	stats.BytesReceived += 64
	decision := detector.observe(http3DegradationSample{
		At: start.Add(5 * http3DegradationSampleInterval), Stats: stats,
		PayloadBytes: downloaded, PayloadReadBytes: downloaded, BlockedReads: 1,
		OldestReadBlockedFor:  5 * http3DegradationSampleInterval,
		LastPayloadProgressAt: start,
	})
	if decision.Rotate || decision.Signals.ReadDemand || decision.Signals.SentNoReceive ||
		decision.Signals.BlackholeWindows != 0 {
		t.Fatalf("QUIC ACK did not reset read-side blackhole: %+v", decision)
	}
}

func TestHTTP3DegradationReadDemandLatchSurvivesRecentWindowUntilPTOEvidence(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 27, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: 10, BytesReceived: 10 << 10,
	}
	const downloaded = uint64(128 << 10)
	detector.observe(http3DegradationSample{
		At: start, Stats: stats, PayloadBytes: downloaded, PayloadReadBytes: downloaded,
	})

	var decision http3DegradationDecision
	for index := 1; index <= 9; index++ {
		// Model an idle QUIC whose first keepalive and a later PTO aren't visible
		// until after the 12-second recent-read window. The demand observed at the
		// first no-inbound sample must remain latched across that delay.
		if index == 6 || index == 8 {
			stats.PacketsSent++
			stats.BytesSent += 1200
		}
		decision = detector.observe(http3DegradationSample{
			At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats,
			PayloadBytes: downloaded, PayloadReadBytes: downloaded, BlockedReads: 1,
			OldestReadBlockedFor: time.Duration(index) * http3DegradationSampleInterval,
			RecentReadDemand:     index == 1, LastPayloadProgressAt: start,
		})
		if index < 9 && decision.Rotate {
			t.Fatalf("delayed PTO evidence rotated too early at sample %d: %+v", index, decision)
		}
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonUDPBlackhole ||
		!decision.Signals.ReadDemand || decision.Signals.NoReceiveFor <= http3UDPBlackholeRecentReadWindow {
		t.Fatalf("read-demand latch did not survive the recent window: %+v", decision)
	}
}

func TestHTTP3DegradationReadOnlyBlackholeRequiresMultipleOutboundSamples(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 29, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: 10, BytesReceived: 10 << 10,
	}
	const downloaded = uint64(128 << 10)
	detector.observe(http3DegradationSample{
		At: start, Stats: stats, PayloadBytes: downloaded, PayloadReadBytes: downloaded,
	})
	stats.PacketsSent++
	stats.BytesSent += 1200
	for index := 1; index <= 10; index++ {
		decision := detector.observe(http3DegradationSample{
			At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats,
			PayloadBytes: downloaded, PayloadReadBytes: downloaded, BlockedReads: 1,
			OldestReadBlockedFor: time.Duration(index) * http3DegradationSampleInterval,
			RecentReadDemand:     index == 1, LastPayloadProgressAt: start,
		})
		if decision.Rotate || decision.Signals.SentNoReceive {
			t.Fatalf("one read-side outbound burst looked like a blackhole at sample %d: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationUpgradesLatchedSevereLossToUDPBlackhole(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 15, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{
		MinRTT:          80 * time.Millisecond,
		SmoothedRTT:     80 * time.Millisecond,
		PacketsSent:     20,
		BytesSent:       20 << 10,
		PacketsReceived: 20,
		BytesReceived:   20 << 10,
	}
	detector.observe(http3DegradationSample{At: start, Stats: stats, PayloadBytes: 4096})
	stats.PacketsSent += 300
	stats.BytesSent += 600 << 10
	stats.PacketsLost += 100
	stats.BytesLost += 200 << 10
	decision := detector.observe(http3DegradationSample{
		At: start.Add(http3DegradationSampleInterval), Stats: stats, PayloadBytes: 4096,
		BlockedWrites: 1, OldestBlockedFor: http3DegradationSingleWriteBlock,
		LastPayloadProgressAt: start,
	})
	if !decision.Rotate || decision.Reason != http3DegradationReasonSevereLossAndWrite {
		t.Fatalf("initial degradation = %+v, want severe loss", decision)
	}

	for index := 2; index <= 5; index++ {
		stats.PacketsSent++
		stats.BytesSent += 1200
		decision = detector.observe(http3DegradationSample{
			At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats, PayloadBytes: 4096,
			BlockedWrites: 1, OldestBlockedFor: time.Duration(index) * http3DegradationSampleInterval,
			LastPayloadProgressAt: start,
		})
	}
	if !decision.Rotate || decision.Reason != http3DegradationReasonUDPBlackhole || !decision.Signals.UDPBlackhole {
		t.Fatalf("latched degradation did not upgrade to blackhole: %+v", decision)
	}
}

func TestHTTP3DegradationUDPBlackholeRequiresMultipleOutboundSamples(t *testing.T) {
	start := time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC)
	detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
	stats := quic.ConnectionStats{PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: 10, BytesReceived: 10 << 10}
	detector.observe(http3DegradationSample{At: start, Stats: stats, PayloadBytes: 1024})
	stats.PacketsSent++
	stats.BytesSent += 1200
	for index := 1; index <= 10; index++ {
		decision := detector.observe(http3DegradationSample{
			At:                    start.Add(time.Duration(index) * http3DegradationSampleInterval),
			Stats:                 stats,
			PayloadBytes:          1024,
			BlockedWrites:         1,
			OldestBlockedFor:      time.Duration(index) * http3DegradationSampleInterval,
			LastPayloadProgressAt: start,
		})
		if decision.Rotate || decision.Signals.SentNoReceive {
			t.Fatalf("one outbound burst looked like a sustained blackhole at %d: %+v", index, decision)
		}
	}
}

func TestHTTP3DegradationUDPBlackholeResetsOnReceivePayloadAndSampleGap(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*quic.ConnectionStats, *uint64)
		gap    time.Duration
	}{
		{name: "QUIC ACK", mutate: func(stats *quic.ConnectionStats, _ *uint64) { stats.PacketsReceived++ }},
		{name: "payload progress", mutate: func(_ *quic.ConnectionStats, payload *uint64) { *payload += 1024 }},
		{name: "sleep gap", gap: http3UDPBlackholeMaxSampleGap + time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
			detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
			stats := quic.ConnectionStats{PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: 10, BytesReceived: 10 << 10}
			payload := uint64(1024)
			detector.observe(http3DegradationSample{At: start, Stats: stats, PayloadBytes: payload})
			for index := 1; index <= 4; index++ {
				stats.PacketsSent++
				stats.BytesSent += 1200
				detector.observe(http3DegradationSample{
					At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats,
					PayloadBytes: payload, BlockedWrites: 1,
					OldestBlockedFor: time.Duration(index) * http3DegradationSampleInterval, LastPayloadProgressAt: start,
				})
			}
			if test.mutate != nil {
				test.mutate(&stats, &payload)
			}
			gap := test.gap
			if gap == 0 {
				gap = http3DegradationSampleInterval
			}
			at := start.Add(4*http3DegradationSampleInterval + gap)
			decision := detector.observe(http3DegradationSample{
				At: at, Stats: stats, PayloadBytes: payload, BlockedWrites: 1,
				OldestBlockedFor: at.Sub(start), LastPayloadProgressAt: start,
			})
			if decision.Rotate || decision.Signals.BlackholeWindows != 0 || decision.Signals.SentNoReceive {
				t.Fatalf("reset sample retained blackhole state: %+v", decision)
			}
		})
	}
}

func TestHTTP3DegradationUDPBlackholeNeedsPriorBidirectionalTrafficAndPendingWrite(t *testing.T) {
	start := time.Date(2026, 9, 1, 9, 30, 0, 0, time.UTC)
	for _, test := range []struct {
		name          string
		initialRecv   uint64
		blockedWrites int
	}{
		{name: "never received", initialRecv: 0, blockedWrites: 1},
		{name: "idle tunnel", initialRecv: 10, blockedWrites: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			detector := newHTTP3DegradationDetector(start.Add(-http3DegradationWarmup))
			stats := quic.ConnectionStats{PacketsSent: 10, BytesSent: 10 << 10, PacketsReceived: test.initialRecv}
			detector.observe(http3DegradationSample{At: start, Stats: stats, PayloadBytes: 1024})
			for index := 1; index <= 8; index++ {
				stats.PacketsSent++
				stats.BytesSent += 1200
				decision := detector.observe(http3DegradationSample{
					At: start.Add(time.Duration(index) * http3DegradationSampleInterval), Stats: stats,
					PayloadBytes: 1024, BlockedWrites: test.blockedWrites,
					OldestBlockedFor: time.Duration(index) * http3DegradationSampleInterval, LastPayloadProgressAt: start,
				})
				if decision.Rotate || decision.Signals.UDPBlackhole {
					t.Fatalf("sample %d false-positive: %+v", index, decision)
				}
			}
		})
	}
}
