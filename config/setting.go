package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

// projectConfig 保存从 setting.json 读取的顶层配置。
type projectConfig struct {
	Log   log     `json:"log"`
	Rules []*Rule `json:"rules"`
}

type log struct {
	Level   string `json:"level"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Date    string `json:"date"`
}

// Rule 描述一个监听端口以及接入流量的路由策略。
type Rule struct {
	Name    string `json:"name"`
	Listen  string `json:"listen"`
	Mode    string `json:"mode"`
	Prewarm bool   `json:"prewarm"`
	Targets []*struct {
		Regexp  string         `json:"regexp"`
		Re      *regexp.Regexp `json:"-"`
		Address string         `json:"address"`
	} `json:"targets"`
	Timeout   uint64          `json:"timeout"`
	Blacklist map[string]bool `json:"blacklist"`
}

// （单边模式）已移除加速端和丢包自适应的旧配置。

// GlobalCfg 指向全局生效的配置对象。
var GlobalCfg *projectConfig

func init() {
	// 支持通过环境变量覆盖配置文件路径
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
}

// Reload 从指定路径重载配置，并执行默认值填充与校验。
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
	GlobalCfg = cfg
	return nil
}

// verify 校验规则配置，并在需要时编译正则。
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
