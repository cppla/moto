package config

import "testing"

func TestConnectProxyBrowserProfileValidation(t *testing.T) {
	for _, profile := range []string{"", BrowserProfileChrome} {
		c := &ConnectProxyConfig{Protocols: []string{ConnectProxyH3, ConnectProxyH2}, BrowserProfile: profile}
		if err := c.Validate(); err != nil {
			t.Fatalf("profile %q: %v", profile, err)
		}
	}
	for _, profile := range []string{"Chrome", "chrome-latest", " chrome-133", "firefox"} {
		c := &ConnectProxyConfig{BrowserProfile: profile}
		if err := c.Validate(); err == nil {
			t.Fatalf("unsupported profile %q accepted", profile)
		}
	}
}

func TestBrowserProfileStrictJSON(t *testing.T) {
	valid := `{"rules":[{"targets":[{"connectProxy":{"protocols":["h3","h2"],"browserProfile":"chrome"}}]}]}`
	if err := validateStrictConfigJSON([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`{"rules":[{"targets":[{"connectProxy":{"BrowserProfile":"chrome"}}]}]}`,
		`{"rules":[{"targets":[{"connectProxy":{"browserProfile":"chrome","browserProfile":""}}]}]}`,
	} {
		if err := validateStrictConfigJSON([]byte(input)); err == nil {
			t.Fatal("ambiguous profile field accepted")
		}
	}
}
