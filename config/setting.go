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

// (single-sided mode) accelerator and loss adaptation are removed

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
