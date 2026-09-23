package controller

import (
	"moto/config"
	"strings"
	"testing"
	"time"
)

func TestLearningMetricsExposeBoundedSemantics(t *testing.T) {
	var output strings.Builder
	renderLearningSnapshot(&output, []routeLearningGauge{{
		rule: "learning", target: "proxy.example:443", protocol: "h2", preferred: true,
		estimate: routeLearningEstimate{Known: true, Samples: 3, Latency: 100 * time.Millisecond, Cost: 200 * time.Millisecond, LastObservation: time.Unix(1700000000, 0)},
	}}, []routeLearningDecisionGauge{{"learning", "quality", 2}, {"learning", "explore", 1}, {"learning", "secret-reason", 99}})
	body := output.String()
	for _, want := range []string{
		`moto_route_learning_samples{rule="learning",target="proxy.example:443",protocol="h2"} 3`,
		`moto_route_learning_confidence{rule="learning",target="proxy.example:443",protocol="h2"} 1`,
		`moto_route_learning_setup_seconds{rule="learning",target="proxy.example:443",protocol="h2"} 0.1`,
		`moto_route_learning_cost_seconds{rule="learning",target="proxy.example:443",protocol="h2"} 0.2`,
		`moto_route_learning_last_observation_timestamp_seconds{rule="learning",target="proxy.example:443",protocol="h2"} 1.7e+09`,
		`moto_route_learning_preferred{rule="learning",target="proxy.example:443",protocol="h2"} 1`,
		`moto_route_learning_decisions_total{rule="learning",reason="quality"} 2`,
		`moto_route_learning_decisions_total{rule="learning",reason="explore"} 1`,
		"not an actual traffic winner", "not a success probability",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in metrics:\n%s", want, body)
		}
	}
	if strings.Contains(body, "secret-reason") {
		t.Fatal("unbounded decision reason escaped into metrics")
	}
}

func TestLearningMetricsConfidenceDoesNotClaimUnsampledSuccess(t *testing.T) {
	for _, estimate := range []routeLearningEstimate{
		{}, {Samples: 20},
		{Samples: 20, Latency: time.Millisecond, LastObservation: time.Now()},
	} {
		if got := learningConfidence(estimate); got < 0 || got >= 1 {
			t.Fatalf("insufficient evidence confidence = %v", got)
		}
	}
	var output strings.Builder
	renderLearningSnapshot(&output, []routeLearningGauge{{rule: "fresh", target: "proxy.example:443", protocol: "h3"}}, nil)
	if !strings.Contains(output.String(), `moto_route_learning_last_observation_timestamp_seconds{rule="fresh",target="proxy.example:443",protocol="h3"} 0`) {
		t.Fatal("zero observation timestamp is not rendered as zero")
	}
}

func TestLearningMetricsNeverExposeInternalRuleIdentity(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := &config.Rule{Name: "public-rule", Listen: "127.0.0.1:9005", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{{Address: "proxy.example:443", ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{"h2"}, BasicAuth: &config.BasicAuthConfig{Username: "private-user", Password: "private-password"},
		}}},
	}
	key := boostRuleKey(rule)
	runtime.learningPolicy.rules[key] = &routeLearningPolicyState{rule: rule, decisions: map[string]uint64{"quality": 1}}
	runtime.learning.observeSetup(routeLearningKey{key, "proxy.example:443", "h2"}, time.Millisecond, nil, time.Now())
	var output strings.Builder
	runtime.renderLearningGauges(&output)
	body := output.String()
	for _, secret := range []string{key, "private-user", "private-password", "127.0.0.1:9005"} {
		if strings.Contains(body, secret) {
			t.Fatal("learning metrics exposed private configuration identity")
		}
	}
	if !strings.Contains(body, `rule="public-rule",target="proxy.example:443",protocol="h2"`) {
		t.Fatal("public route labels missing")
	}
}
