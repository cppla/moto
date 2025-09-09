package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

// Accelerator config enables dual TCP tunnels, duplication and roles.
// When enabled with role "client", traffic from the 4 modes will be proxied
// through persistent tunnels to the remote accelerator server which connects
// to the selected target. When role is "server", the process listens for
// tunnel connections and performs the actual target dial-out.
type Accelerator struct {
	Enabled bool   `json:"enabled"`
	Role    string `json:"role"` // client | server
	// For client role: Remote is the address of the accelerator server, e.g. "1.2.3.4:9900"
	Remote string `json:"remote"`
	// For server role: Listen is the address for accelerator server to listen on, e.g. ":9900"
	Listen string `json:"listen"`
	// Number of persistent TCP tunnels between client and server (auto if loss adaptation enabled)
	Tunnels int `json:"tunnels"`
	// Duplication factor per frame (legacy, ignored when loss adaptation enabled)
	Duplication int `json:"duplication"`
	// FrameSize controls the max payload per frame in bytes (default 8192)
	FrameSize int `json:"frameSize"`
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
	buf, err := ioutil.ReadFile("config/setting.json")
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
				GlobalCfg.Accelerator.Tunnels = 5 // support up to 5x duplication
			}
		} else {
			if GlobalCfg.Accelerator.Tunnels <= 0 {
				GlobalCfg.Accelerator.Tunnels = 2
			}
			if GlobalCfg.Accelerator.Duplication <= 0 {
				GlobalCfg.Accelerator.Duplication = 1
			}
			if GlobalCfg.Accelerator.Duplication > 5 {
				GlobalCfg.Accelerator.Duplication = 5
			}
		}
		if GlobalCfg.Accelerator.FrameSize <= 0 {
			GlobalCfg.Accelerator.FrameSize = 8192
		}
		if GlobalCfg.Accelerator.Role == "client" && GlobalCfg.Accelerator.Remote == "" && GlobalCfg.Accelerator.Enabled {
			fmt.Printf("accelerator role=client requires remote address\n")
		}
		if GlobalCfg.Accelerator.Role == "server" && GlobalCfg.Accelerator.Listen == "" && GlobalCfg.Accelerator.Enabled {
			fmt.Printf("accelerator role=server requires listen address\n")
		}
	}

	// Defaults for loss adaptation and validation
	if GlobalCfg.LossAdaptation == nil {
		GlobalCfg.LossAdaptation = &LossAdaptation{Enabled: true, WindowSeconds: 10, ProbeIntervalMs: 500,
			Rules: []LossRule{{LossBelow: 1, Dup: 1}, {LossBelow: 10, Dup: 2}, {LossBelow: 20, Dup: 3}, {LossBelow: 30, Dup: 4}, {LossBelow: 101, Dup: 5}}}
	} else {
		if GlobalCfg.LossAdaptation.WindowSeconds <= 0 {
			GlobalCfg.LossAdaptation.WindowSeconds = 10
		}
		if GlobalCfg.LossAdaptation.ProbeIntervalMs <= 0 {
			GlobalCfg.LossAdaptation.ProbeIntervalMs = 500
		}
		if len(GlobalCfg.LossAdaptation.Rules) == 0 {
			GlobalCfg.LossAdaptation.Rules = []LossRule{{LossBelow: 1, Dup: 1}, {LossBelow: 10, Dup: 2}, {LossBelow: 20, Dup: 3}, {LossBelow: 30, Dup: 4}, {LossBelow: 101, Dup: 5}}
		}
	}

	for i, v := range GlobalCfg.Rules {
		if err := v.verify(); err != nil {
			fmt.Printf("verity rule failed at pos %d : %s\n", i, err.Error())
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
