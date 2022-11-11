package config

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type OAuth2ProxyConfig struct {
	Address   string `yaml:"address"`
	AuthURL   string `yaml:"authURL"`
	SignInURL string `yaml:"signInURL"`
}

func NewOAuth2ProxyConfig(configFile string) (*OAuth2ProxyConfig, error) {
	cfg := &OAuth2ProxyConfig{}

	if configFile != "" {
		data, err := ioutil.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal(data, cfg)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("config file path is required")
	}

	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	if cfg.Address == "" {
		cfg.Address = ":9080"
	}

	return cfg, nil
}

func (cfg *OAuth2ProxyConfig) Validate() error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{cfg.AuthURL == "", "no authURL specified"},
		{cfg.SignInURL == "", "no signInURL specified"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid config: %s", check.errMsg)
		}
	}

	return nil
}
