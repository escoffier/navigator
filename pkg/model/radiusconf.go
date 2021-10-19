package model

import (
	"encoding/json"
	"fmt"
	"net/url"
)

type RadiusServerConf struct {
	Enable  bool   `json:"enable"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Network string `json:"network"`
	Secret  string `json:"secret"`
}

var (
	DefaultRadiusServerConf = RadiusServerConf{}
)

const (
	RadiusConfKey = "radius-conf-key"
)

func (conf *RadiusServerConf) Encode() []byte {
	jsonBytes, _ := json.Marshal(conf)
	return jsonBytes
}

func (conf *RadiusServerConf) Decode(data []byte) error {
	return json.Unmarshal(data, conf)
}

func (conf *RadiusServerConf) Check() error {
	if !conf.Enable {
		return nil
	}
	_, err := url.Parse(conf.Addr)
	if err != nil {
		return fmt.Errorf("invalid url:%s", err)
	}

	if conf.Port <= 0 {
		return fmt.Errorf("invalid port:%d", conf.Port)
	}

	if conf.Network != "udp" && conf.Network != "tcp" {
		return fmt.Errorf("invalid network:%s", conf.Network)
	}

	if conf.Secret == "" {
		return fmt.Errorf("invalid secret:%s", conf.Secret)
	}

	return nil
}
