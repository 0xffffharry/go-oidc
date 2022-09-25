package config

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"oidc/proxy"
	"os"
)

type Config struct {
	Servers []proxy.ProxyConfig `json:"server"`
}

func ParseConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.NewDecoder(f).Decode(&config)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	if config.Servers == nil || len(config.Servers) == 0 {
		return nil, errors.New("no server config found")
	}
	cache := make(map[string]bool)
	for k, v := range config.Servers {
		if _, ok := cache[v.Tag]; ok {
			return nil, errors.New("duplicate Tag")
		} else {
			cache[v.Tag] = true
		}
		if v.Listen == "" {
			return nil, errors.New("no Listen")
		}
		host, port, err := net.SplitHostPort(v.Listen)
		if err != nil {
			return nil, errors.New("invalid Listen")
		}
		hostWithPort := net.JoinHostPort(host, port)
		if _, ok := cache[hostWithPort]; ok {
			return nil, errors.New("duplicate Listen")
		} else {
			cache[hostWithPort] = true
		}
		config.Servers[k].Listen = hostWithPort
		discoveryUri, err := url.Parse(v.DiscoveryUri)
		if err != nil {
			return nil, errors.New("invalid DiscoveryUri")
		}
		config.Servers[k].DiscoveryUri = discoveryUri.String()
		if v.ClientID == "" {
			return nil, errors.New("no ClientID")
		}
		if v.ClientSecret == "" {
			return nil, errors.New("no ClientSecret")
		}
		if v.RedirectPath == "" {
			config.Servers[k].RedirectPath = "/redirect_uri"
		} else if v.RedirectPath[0] != '/' {
			config.Servers[k].RedirectPath = "/" + v.RedirectPath
		}
		if v.RedirectPath == "/" {
			config.Servers[k].RedirectPath = "/redirect_uri"
		}
		if v.LogoutPath == "" {
			config.Servers[k].LogoutPath = "/logout"
		} else if v.LogoutPath[0] != '/' {
			config.Servers[k].LogoutPath = "/" + v.LogoutPath
		}
		if v.LogoutPath == "/" {
			config.Servers[k].LogoutPath = "/logout"
		}
		if v.AfterLogoutUri != "" {
			afterLogoutUri, err := url.Parse(v.AfterLogoutUri)
			if err != nil {
				return nil, errors.New("invalid AfterLogoutUri")
			}
			config.Servers[k].AfterLogoutUri = afterLogoutUri.String()
		}
		if v.Scope == nil || len(v.Scope) == 0 {
			config.Servers[k].Scope = []string{"openid", "profile", "email"}
		}
		if v.Upstream == "" {
			return nil, errors.New("no Upstream")
		}
	}
	return &config, nil
}
