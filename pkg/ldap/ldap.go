package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	ErrUserPasswordNotMatch = errors.New("user password not match")
)

func Login(account, password string, conf *model.LdapServerConf, tlsConf *tls.Config) (string, error) {
	l, err := dial(conf, tlsConf)
	if err != nil {
		return "", err
	}
	defer l.Close()

	err = l.Bind(conf.BindDN, conf.BindPassword)
	if err != nil {
		return "", fmt.Errorf("bind fail, err:%w", err)
	}

	dn, group, err := getUserInfo(l, account, conf)
	if err != nil {
		return "", err
	}

	err = l.Bind(dn, password)
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return "", ErrUserPasswordNotMatch
		}
		return "", err
	}

	return group, nil
}

func GetUserGroup(account string, conf *model.LdapServerConf, tlsConf *tls.Config) (string, error) {
	l, err := dial(conf, tlsConf)
	if err != nil {
		return "", err
	}
	defer l.Close()

	err = l.Bind(conf.BindDN, conf.BindPassword)
	if err != nil {
		return "", fmt.Errorf("bind fail, err:%w", err)
	}

	_, group, err := getUserInfo(l, account, conf)
	return group, err
}

const (
	timeout = time.Second * 3
)

func dial(conf *model.LdapServerConf, tlsConf *tls.Config) (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error
	if conf.ConnType == model.LdapModeTLS {
		l, err = ldap.DialURL(fmt.Sprintf("%s:%d", conf.Addr, conf.Port),
			ldap.DialWithTLSConfig(tlsConf), ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	} else {
		l, err = ldap.DialURL(fmt.Sprintf("%s:%d", conf.Addr, conf.Port),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	}
	if err != nil {
		return nil, fmt.Errorf("dial fail, err:%w", err)
	}

	l.SetTimeout(timeout)
	if conf.ConnType == model.LdapModeStartTLS {
		err = l.StartTLS(tlsConf)
		if err != nil {
			l.Close()
			return nil, err
		}
	}

	return l, nil
}

func getUserInfo(l *ldap.Conn, account string, conf *model.LdapServerConf) (string, string, error) {
	searchRequest := ldap.NewSearchRequest(
		conf.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(conf.UserFilter, account),
		[]string{conf.GroupField},
		nil,
	)
	searchResult, err := l.Search(searchRequest)
	if err != nil {
		return "", "", fmt.Errorf("search fail, err:%w", err)
	}

	if len(searchResult.Entries) == 0 {
		return "", "", ErrUserPasswordNotMatch
	}

	dn := searchResult.Entries[0].DN

	for _, attr := range searchResult.Entries[0].Attributes {
		if attr.Name == conf.GroupField {
			if len(attr.Values) > 0 {
				return dn, attr.Values[0], nil
			}
			break
		}
	}

	return dn, "", nil
}
