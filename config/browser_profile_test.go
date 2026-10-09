package config

import (
	"strings"
	"testing"
)

func TestConnectProxyWithoutBrowserProfileValidation(t *testing.T) {
	for _, protocols := range [][]string{
		nil,
		{ConnectProxyH2},
		{ConnectProxyH3},
		{ConnectProxyH3, ConnectProxyH2},
		{ConnectProxyH2, ConnectProxyH3},
	} {
		c := &ConnectProxyConfig{Protocols: protocols}
		if err := c.Validate(); err != nil {
			t.Fatalf("protocols %q without a profile: %v", protocols, err)
		}
	}
}

func TestBrowserProfileStrictJSON(t *testing.T) {
	valid := `{"rules":[{"targets":[{"connectProxy":{"protocols":["h3","h2"]}}]}]}`
	if err := validateStrictConfigJSON([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`{"rules":[{"targets":[{"connectProxy":{"browserProfile":"chrome"}}]}]}`,
		`{"rules":[{"targets":[{"connectProxy":{"browserProfile":""}}]}]}`,
		`{"rules":[{"targets":[{"connectProxy":{"browserProfile":null}}]}]}`,
		`{"rules":[{"targets":[{"connectProxy":{"BrowserProfile":"chrome"}}]}]}`,
		`{"rules":[{"targets":[{"connectProxy":{"browserProfile":"chrome","browserProfile":""}}]}]}`,
	} {
		if err := validateStrictConfigJSON([]byte(input)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "browserprofile") {
			t.Fatalf("removed profile field must be rejected explicitly: %v", err)
		}
	}
}
