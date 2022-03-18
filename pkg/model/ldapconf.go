package model

import (
	"fmt"
	"net/url"

	json "github.com/json-iterator/go"
)

const (
	LdapModeNonTLS   = "NON-TLS"
	LdapModeTLS      = "TLS"
	LdapModeStartTLS = "StartTLS"
)

type LdapServerConf struct {
	Enable             bool   `json:"enable"`
	Addr               string `json:"addr"`
	Port               int    `json:"port"`
	BaseDN             string `json:"baseDN"`
	UserFilter         string `json:"userFilter"`
	ConnType           string `json:"connType"`
	BindDN             string `json:"bindDN"`
	BindPassword       string `json:"bindPassword"`
	GroupField         string `json:"groupField"`
	ServerNameOverride string `json:"serverNameOverride"`
}

var (
	DefaultLdapServerConf = LdapServerConf{}
)

const (
	LdapConfKey       = "ldap-conf-key"
	LdapCAKey         = "ldap-ca-key"
	LdapClientCertKey = "ldap-client-cert-key"
	LdapClientKey     = "ldap-client-key"
)

func (conf *LdapServerConf) Encode() []byte {
	jsonBytes, _ := json.Marshal(conf)
	return jsonBytes
}

func (conf *LdapServerConf) Decode(data []byte) error {
	return json.Unmarshal(data, conf)
}

func (conf *LdapServerConf) Check() error {
	if !conf.Enable {
		return nil
	}

	if conf.ConnType != LdapModeNonTLS && conf.ConnType != LdapModeTLS && conf.ConnType != LdapModeStartTLS {
		return fmt.Errorf("invalid connType:%s", conf.ConnType)
	}

	u, err := url.Parse(conf.Addr)
	if err != nil {
		return fmt.Errorf("invalid url:%s", err)
	}

	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("invalid url:%s", err)
	}

	if (u.Scheme == "ldap" && conf.ConnType == LdapModeTLS) || (u.Scheme == "ldaps" && conf.ConnType != LdapModeTLS) {
		return fmt.Errorf("connType:%s, url:%s not match", conf.ConnType, conf.Addr)
	}

	if conf.Port <= 0 {
		return fmt.Errorf("invalid port:%d", conf.Port)
	}
	if conf.BaseDN == "" {
		return fmt.Errorf("invalid baseDN:%s", conf.BaseDN)
	}
	if conf.UserFilter == "" {
		return fmt.Errorf("invalid userFilter:%s", conf.UserFilter)
	}
	if conf.BindDN == "" {
		return fmt.Errorf("invalid bindDN:%s", conf.BindDN)
	}
	if conf.GroupField == "" {
		return fmt.Errorf("invalid group field:%s", conf.GroupField)
	}

	return nil
}
