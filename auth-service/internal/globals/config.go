package globals

import "net"

const (
	AuthProviderRadius = "radius"
	AuthProviderLDAP   = "ldap"
)

type WebSrvConfigProvider interface {
	GetAddress() string
	GetPort() int
	GetAuthApiKey() string
	IsMonitoringEnabled() bool
	GetMonitoringApiKey() string
	GetMonitoringPath() string
	IsSSLEnabled() bool
	PrivateKey() string
	Certificate() string
}

type ConfigProvider interface {
	WebSrvConfig() WebSrvConfigProvider
}

type IRadiusServersProvider interface {
	AppLogger() AppLogger
	RadiusServer(i int) (RadiusProvider, error)
	NumAuthServers() int
	GetAvailableRadiusAuthServer() (RadiusProvider, error)
	NASID() string
	NASIpV4Addr() net.IP
	NASPort() uint32
}

type RadiusProvider interface {
	GetAddress() string
	GetPort() int
	GetSecret() string
	GetProto() string
	GetResponseTimeoutSec() int
	GetName() string
}

type LDAPServerProvider interface {
	LDAPURL() string
	GetUseSSL() bool
}

type AuthClientProvider interface {
	AuthenticateUser(user, pass, clientIp string) (bool, *NetworkData, error)
	CheckAuthenticateUser(u, p string, serverIdx int) (bool, error)
}

type NetworkData struct {
	IP      string `json:"ip,omitempty"`
	Netmask string `json:"netmask,omitempty"`
}

type MonitoringStatusResponse struct {
	ID   int    `json:"status_id"`
	Text string `json:"status_text"`
	Msg  string `json:"msg,omitempty"`
}

const (
	StatusOk    = 1
	StatusWarn  = 2
	StatusError = 3
)

func StatusText(s int) string {
	switch s {
	case StatusOk:
		return "ok"
	case StatusWarn:
		return "warn"
	case StatusError:
		return "err"
	}
	return "err"
}
