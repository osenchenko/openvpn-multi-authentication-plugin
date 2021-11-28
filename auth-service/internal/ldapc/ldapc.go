package ldapc

import (
	"auth-service/internal/globals"
	"crypto/tls"
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
)

type ConfigProvider interface {
	GetLDAPVerifyCert() bool
	GetSearchBase() string
	GetSearchFilter() string
	GetBindUserDN() string
	GetPassword() string
	GetAvailableAuthLDAPServer() (globals.LDAPServerProvider, error)
	LDAPAuthServer(idx int) (globals.LDAPServerProvider, error)
	AppLogger() globals.AppLogger
}

type LDAPAuthClient struct {
	c ConfigProvider
	// ldapURL      string
	verifyCert bool
	// useSSL       bool
	searchBase   string
	searchFilter string
	bindDN       string
	pass         string
	tlsCfg       *tls.Config
	l            globals.AppLogger
}

func NewClient(c ConfigProvider) *LDAPAuthClient {
	var tlsCfg tls.Config
	if c.GetLDAPVerifyCert() {
		tlsCfg = tls.Config{InsecureSkipVerify: false}
	} else {
		tlsCfg = tls.Config{InsecureSkipVerify: true}
	}

	// filter := fmt.Sprintf("(CN=%s)", ldap.EscapeFilter(user))
	return &LDAPAuthClient{
		c: c,
		// ldapURL:      c.URL(),
		verifyCert: c.GetLDAPVerifyCert(),
		// useSSL:       c.GetUseSSL(),
		searchBase:   c.GetSearchBase(),
		searchFilter: c.GetSearchFilter(),
		bindDN:       c.GetBindUserDN(),
		pass:         c.GetPassword(),
		tlsCfg:       &tlsCfg,
		l:            c.AppLogger(),
	}
}

func (a *LDAPAuthClient) authenticate(login, pass string, ldapURL string, useSSL bool) (bool, error) {
	var c *ldap.Conn
	var err error
	if useSSL {
		a.l.Debugf("dial ldaps url: %s", ldapURL)
		c, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(a.tlsCfg))
	} else {
		a.l.Debugf("dial ldap url: %s", ldapURL)
		c, err = ldap.DialURL(ldapURL)
	}
	if err != nil {
		return false, err
	}
	defer c.Close()

	err = c.Bind(a.bindDN, a.pass)
	if err != nil {
		return false, fmt.Errorf("failed to bind dn. %s", err)
	}
	filter := fmt.Sprintf(a.searchFilter, login)
	a.l.Debugf("ldap search filter: %s", filter)
	sr, err := c.Search(ldap.NewSearchRequest(
		a.searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn", "sAMAccountName", "mail", "givenName", "sn"},
		nil,
	))
	if err != nil {
		return false, err
	}
	if len(sr.Entries) == 0 {
		return false, fmt.Errorf("user with login %s not found", login)
	}

	err = c.Bind(sr.Entries[0].DN, pass)
	if err != nil {
		return false, fmt.Errorf("failed to authenticate user with login %s. error: %s", login, err)
	}
	return true, nil
}

func (a *LDAPAuthClient) AuthenticateUser(u, p, ip string) (bool, *globals.NetworkData, error) {
	// authResult := false
	srv, err := a.c.GetAvailableAuthLDAPServer()
	if err != nil {
		return false, nil, err
	}
	authResult, err := a.authenticate(u, p, srv.LDAPURL(), srv.GetUseSSL())
	return authResult, nil, err
}

func (a *LDAPAuthClient) CheckAuthenticateUser(u, p string, serverIdx int) (bool, error) {
	srv, err := a.c.LDAPAuthServer(serverIdx)
	if err != nil {
		return false, err
	}
	return a.authenticate(u, p, srv.LDAPURL(), srv.GetUseSSL())
}
