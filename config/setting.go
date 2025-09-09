package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

type projectConfig struct {
	Log   log     `json:"log"`
	Rules []*Rule `json:"rules"`
	Wafs  []*Waf  `json:"wafs"`
	// Accelerator provides optional weak-network acceleration overlay
	Accelerator *Accelerator `json:"accelerator"`
	// LossAdaptation configures dynamic duplication based on observed loss
	LossAdaptation *LossAdaptation `json:"lossAdaptation"`
}

type log struct {
	Level   string `json:"level"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Date    string `json:"date"`
}

type Waf struct {
	Name         string   `json:"name"`
	Blackcountry []string `json:"blackcountry"`
	Threshold    uint64   `json:"threshold"`
	Findtime     uint64   `json:"findtime"`
	Bantime      uint64   `json:"bantime"`
}

type Rule struct {
	Name    string `json:"name"`
	Listen  string `json:"listen"`
	Mode    string `json:"mode"`
	Targets []*struct {
		Regexp  string         `json:"regexp"`
		Re      *regexp.Regexp `json:"-"`
		Address string         `json:"address"`
	} `json:"targets"`
	Timeout   uint64          `json:"timeout"`
	Blacklist map[string]bool `json:"blacklist"`
}

// Accelerator config enables multi-tunnel acceleration roles.
// When enabled with role "client", traffic from the 4 modes will be proxied
// through persistent tunnels to the remote accelerator server which connects
// to the selected target. When role is "server", the process listens for
// tunnel connections and performs the actual target dial-out.
type Accelerator struct {
	Enabled bool   `json:"enabled"`
	Role    string `json:"role"` // client | server
	// Client role: multiple remote endpoints for multi-path
	Remotes []string `json:"remotes"`
	// For server role: Listen is the address for accelerator server to listen on, e.g. ":9900"
	Listen string `json:"listen"`
	// Number of persistent TCP tunnels between client and server (auto if loss adaptation enabled)
	Tunnels int `json:"tunnels"`
	// FrameSize controls the max payload per frame in bytes (default 32768)
	FrameSize int `json:"frameSize"`
	// Transport selects tunnel transport: "tcp" (default) or "quic"
	Transport string `json:"transport"`
	// TLS options for QUIC (nginx-like). If these are empty on server, a self-signed cert will be used.
	CertificateFile string `json:"certificate-file"`
	PrivateKeyFile  string `json:"private-key-file"`
}

// LossAdaptation maps observed loss(%) to duplication factor.
type LossAdaptation struct {
	Enabled         bool       `json:"enabled"`
	WindowSeconds   int        `json:"windowSeconds"`
	ProbeIntervalMs int        `json:"probeIntervalMs"`
	Rules           []LossRule `json:"rules"`
}

type LossRule struct {
	LossBelow float64 `json:"lossBelow"` // e.g. 1, 10, 20, 30 meaning %
	Dup       int     `json:"dup"`       // 1..5
}

var GlobalCfg *projectConfig

func init() {
	// Support env override for config file path
	path := os.Getenv("MOTO_CONFIG")
	if path == "" {
		path = "config/setting.json"
	}
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("failed to load setting.json: %s\n", err.Error())
	}

	if err := json.Unmarshal(buf, &GlobalCfg); err != nil {
		fmt.Printf("failed to load setting.json: %s\n", err.Error())
	}

	if len(GlobalCfg.Rules) == 0 {
		fmt.Printf("empty rule\n")
	}

	if GlobalCfg.Accelerator != nil {
		// defaults and quick validation
		// if loss adaptation is enabled we will auto-size tunnels; else keep legacy defaults
		if GlobalCfg.LossAdaptation != nil && GlobalCfg.LossAdaptation.Enabled {
			if GlobalCfg.Accelerator.Tunnels <= 0 {
				GlobalCfg.Accelerator.Tunnels = 3 // conservative default
			}
		} else {
			if GlobalCfg.Accelerator.Tunnels <= 0 {
				GlobalCfg.Accelerator.Tunnels = 2
			}
		}
		if GlobalCfg.Accelerator.FrameSize <= 0 {
			GlobalCfg.Accelerator.FrameSize = 32768
		}
		if GlobalCfg.Accelerator.Transport == "" {
			GlobalCfg.Accelerator.Transport = "tcp"
		}
		if GlobalCfg.Accelerator.Transport != "tcp" && GlobalCfg.Accelerator.Transport != "quic" {
			fmt.Printf("invalid transport: %s, fallback to tcp\n", GlobalCfg.Accelerator.Transport)
			GlobalCfg.Accelerator.Transport = "tcp"
		}
		if GlobalCfg.Accelerator.Role == "client" && GlobalCfg.Accelerator.Enabled && len(GlobalCfg.Accelerator.Remotes) == 0 {
			fmt.Printf("accelerator role=client requires remotes\n")
		}
		if GlobalCfg.Accelerator.Role == "server" && GlobalCfg.Accelerator.Listen == "" && GlobalCfg.Accelerator.Enabled {
			fmt.Printf("accelerator role=server requires listen address\n")
		}
	}

	// Defaults for loss adaptation and validation
	if GlobalCfg.LossAdaptation == nil {
		GlobalCfg.LossAdaptation = &LossAdaptation{Enabled: true, WindowSeconds: 10, ProbeIntervalMs: 1000,
			Rules: []LossRule{{LossBelow: 1, Dup: 1}, {LossBelow: 15, Dup: 2}, {LossBelow: 25, Dup: 3}, {LossBelow: 35, Dup: 4}, {LossBelow: 101, Dup: 5}}}
	} else {
		if GlobalCfg.LossAdaptation.WindowSeconds <= 0 {
			GlobalCfg.LossAdaptation.WindowSeconds = 10
		}
		if GlobalCfg.LossAdaptation.ProbeIntervalMs <= 0 {
			GlobalCfg.LossAdaptation.ProbeIntervalMs = 1000
		}
		if len(GlobalCfg.LossAdaptation.Rules) == 0 {
			GlobalCfg.LossAdaptation.Rules = []LossRule{{LossBelow: 0.5, Dup: 1}, {LossBelow: 5, Dup: 2}, {LossBelow: 10, Dup: 3}, {LossBelow: 20, Dup: 4}, {LossBelow: 101, Dup: 5}}
		}
	}

	for i, v := range GlobalCfg.Rules {
		if err := v.verify(); err != nil {
			fmt.Printf("verify rule failed at pos %d : %s\n", i, err.Error())
		}
	}

	for i, v := range GlobalCfg.Wafs {
		if v.Name == "" {
			fmt.Printf("empty waf name at pos %d\n", i)
		}
		if v.Threshold == 0 {
			fmt.Printf("invalid threshold at pos %d\n", i)
		}
		if v.Findtime == 0 {
			fmt.Printf("invalid findtime at pos %d\n", i)
		}
		if v.Bantime == 0 {
			fmt.Printf("invalid bantime at pos %d\n", i)
		}
		fmt.Println(v)
	}
}

// Reload loads configuration from the given path and applies defaults/validation.
func Reload(path string) error {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg *projectConfig
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return err
	}
	if len(cfg.Rules) == 0 {
		fmt.Printf("empty rule\n")
	}
	if cfg.Accelerator != nil {
		if cfg.LossAdaptation != nil && cfg.LossAdaptation.Enabled {
			if cfg.Accelerator.Tunnels <= 0 {
				cfg.Accelerator.Tunnels = 3
			}
		} else {
			if cfg.Accelerator.Tunnels <= 0 {
				cfg.Accelerator.Tunnels = 2
			}
		}
		if cfg.Accelerator.FrameSize <= 0 {
			cfg.Accelerator.FrameSize = 32768
		}
		if cfg.Accelerator.Transport == "" {
			cfg.Accelerator.Transport = "tcp"
		}
		if cfg.Accelerator.Transport != "tcp" && cfg.Accelerator.Transport != "quic" {
			fmt.Printf("invalid transport: %s, fallback to tcp\n", cfg.Accelerator.Transport)
			cfg.Accelerator.Transport = "tcp"
		}
		if cfg.Accelerator.Role == "client" && cfg.Accelerator.Enabled && len(cfg.Accelerator.Remotes) == 0 {
			fmt.Printf("accelerator role=client requires remotes\n")
		}
		if cfg.Accelerator.Role == "server" && cfg.Accelerator.Listen == "" && cfg.Accelerator.Enabled {
			fmt.Printf("accelerator role=server requires listen address\n")
		}
	}
	if cfg.LossAdaptation == nil {
		cfg.LossAdaptation = &LossAdaptation{Enabled: true, WindowSeconds: 10, ProbeIntervalMs: 1000,
			Rules: []LossRule{{LossBelow: 0.5, Dup: 1}, {LossBelow: 5, Dup: 2}, {LossBelow: 10, Dup: 3}, {LossBelow: 20, Dup: 4}, {LossBelow: 101, Dup: 5}}}
	} else {
		if cfg.LossAdaptation.WindowSeconds <= 0 {
			cfg.LossAdaptation.WindowSeconds = 10
		}
		if cfg.LossAdaptation.ProbeIntervalMs <= 0 {
			cfg.LossAdaptation.ProbeIntervalMs = 1000
		}
		if len(cfg.LossAdaptation.Rules) == 0 {
			cfg.LossAdaptation.Rules = []LossRule{{LossBelow: 0.5, Dup: 1}, {LossBelow: 5, Dup: 2}, {LossBelow: 10, Dup: 3}, {LossBelow: 20, Dup: 4}, {LossBelow: 101, Dup: 5}}
		}
	}
	for i, v := range cfg.Rules {
		if err := v.verify(); err != nil {
			fmt.Printf("verify rule failed at pos %d : %s\n", i, err.Error())
		}
	}
	for i, v := range cfg.Wafs {
		if v.Name == "" {
			fmt.Printf("empty waf name at pos %d\n", i)
		}
		if v.Threshold == 0 {
			fmt.Printf("invalid threshold at pos %d\n", i)
		}
		if v.Findtime == 0 {
			fmt.Printf("invalid findtime at pos %d\n", i)
		}
		if v.Bantime == 0 {
			fmt.Printf("invalid bantime at pos %d\n", i)
		}
		fmt.Println(v)
	}
	GlobalCfg = cfg
	return nil
}

func (c *Rule) verify() error {
	if c.Name == "" {
		return fmt.Errorf("empty name")
	}
	if c.Listen == "" {
		return fmt.Errorf("invalid listen address")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("invalid targets")
	}
	if c.Mode == "regex" {
		if c.Timeout == 0 {
			c.Timeout = 500
		}
	}
	for i, v := range c.Targets {
		if v.Address == "" {
			return fmt.Errorf("invalid address at pos %d", i)
		}
		if c.Mode == "regex" {
			r, err := regexp.Compile(v.Regexp)
			if err != nil {
				return fmt.Errorf("invalid regexp at pos %d : %s", i, err.Error())
			}
			v.Re = r
		}
	}
	return nil
}
