package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
)

type projectConfig struct {
	Log		log   `json:"log"`
	Rules	[]*Rule `json:"rules"`
}

type log struct {
	Level		string	`json:"level"`
	Path		string	`json:"path"`
	Version		string	`json:"version"`
	Date		string	`json:"date"`
}

type Rule struct {
	Name         string				`json:"name"`
	Listen       string				`json:"listen"`
	Mode  		 string				`json:"mode"`
	Targets      []*struct {
		Regexp  string				`json:"regexp"`
		Re		*regexp.Regexp		`json:"-"`
		Address string				`json:"address"`
	} `json:"targets"`
	Timeout		uint64 				`json:"timeout"`
	Blacklist	map[string]bool		`json:"blacklist"`
}

var GlobalCfg *projectConfig

func init() {
	buf, err := ioutil.ReadFile("config/setting.json")
	if err != nil {
		fmt.Errorf("failed to load setting.json: %s", err.Error())
	}

	if err := json.Unmarshal(buf, &GlobalCfg); err != nil {
		fmt.Errorf("failed to load setting.json: %s", err.Error())
	}

	if len(GlobalCfg.Rules) == 0 {
		fmt.Errorf("empty rule")
	}

	for i, v := range GlobalCfg.Rules {
		if err := v.verify(); err != nil {
			fmt.Errorf("verity rule failed at pos %d : %s", i, err.Error())
		}
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