package config

import (
	"auth-service/internal/globals"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type AppConfig struct {
	l  globals.AppLogger
	cf ConfigFile
	// LDAPSrv      []
	// AuthProtocol       string `mapstructure:"auth_protocol" json:"auth_protocol"`
	availableServers   []int
	m                  sync.RWMutex
	unavailableServers []int
	m2                 sync.RWMutex
}

type ConfigFile struct {
	L                Log         `mapstructure:"log" json:"log"`
	Srv              Server      `mapstructure:"web_server" json:"web_server"`
	AuthProviderType string      `mapstructure:"type" json:"type"`
	AuthRadius       *AuthRadius `mapstructure:"radius" json:"radius"`
	AuthCheck        *AuthCheck  `mapstructure:"auth_check" json:"auth_check"`
	AuthLDAP         *AuthLDAP   `mapstructure:"ldap" json:"ldap"`
}

type AuthCheck struct {
	Enable      bool   `mapstructure:"enable" json:"enable"`
	IntervalSec int    `mapstructure:"interval_sec" json:"interval_sec"`
	User        string `mapstructure:"user" json:"user"`
	Pass        string `mapstructure:"pass" json:"pass"`
}

type Server struct {
	Address    string      `mapstructure:"address" json:"listen_address"`
	Port       int         `mapstructure:"port" json:"port"`
	AuthApiKey string      `mapstructure:"auth_api_key" json:"auth_api_key"`
	HTTPS      HTTPSConfig `mapstructure:"https" json:"https"`
	Monitoring Monitoring  `mapstructure:"monitoring" json:"monitoring"`
}

type HTTPSConfig struct {
	Enable      bool   `mapstructure:"enable" json:"enable"`
	PrivateKey  string `mapstructure:"private_key" json:"private_key"`
	Certificate string `mapstructure:"certificate" json:"certificate"`
}

type Monitoring struct {
	Enabled bool   `mapstructure:"enable" json:"enable"`
	Path    string `mapstructure:"path" json:"path"`
	ApiKey  string `mapstructure:"api_key" json:"api_key"`
}

type Log struct {
	File  string `mapstructure:"file" json:"file"`
	Level string `mapstructure:"level" json:"level"`
}

type AuthRadius struct {
	NASID          string      `mapstructure:"nas_id"`
	NASIpV4AddrStr string      `mapstructure:"nas_ipv4_address"`
	nasIpV4Addr    net.IP      `mapstructure:"-"`
	NASPort        int         `mapstructure:"nas_port"`
	RS             []RadiusSrv `mapstructure:"servers"`
}

type AuthLDAP struct {
	BindDN       string       `mapstructure:"bind_dn"`
	Password     string       `mapstructure:"pass"`
	SearchBase   string       `mapstructure:"search_base"`
	SearchFilter string       `mapstructure:"search_filter"`
	VerifyCert   bool         `mapstructure:"verify_cert"`
	LS           []LDAPServer `mapstructure:"servers"`
}

type LDAPServer struct {
	Name               string `mapstructure:"name"`
	Address            string `mapstructure:"address"`
	Port               int    `mapstructure:"port"`
	UseSSL             bool   `mapstructure:"ssl"`
	ResponseTimeoutSec int    `mapstructure:"response_timeout_sec"`
}

func (ls LDAPServer) LDAPURL() string {
	var url string
	if ls.UseSSL {
		url = "ldaps://" + ls.Address + ":" + strconv.Itoa(ls.Port)
	} else {
		url = "ldap://" + ls.Address + ":" + strconv.Itoa(ls.Port)
	}
	return url
}

func (ls LDAPServer) GetUseSSL() bool {
	return ls.UseSSL
}

type RadiusSrv struct {
	Name               string `mapstructure:"name" json:"name"`
	Address            string `mapstructure:"address" json:"address"`
	Port               int    `mapstructure:"port" json:"port"`
	Secret             string `mapstructure:"secret" json:"secret"`
	Proto              string `mapstructure:"protocol" json:"protocol"`
	ResponseTimeoutSec int    `mapstructure:"response_timeout_sec" json:"response_timeout_sec"`
}

func NewConfig() *AppConfig {
	return &AppConfig{
		cf: ConfigFile{
			// Srv: Server{},
			// L:   Log{},
			// AuthCheck:  AuthCheck{},
			// AuthRadius: AuthRadius{},
			// RS:        make([]RadiusSrv, 0, 2),
		},
		availableServers:   make([]int, 0, 10),
		unavailableServers: make([]int, 0, 10),
	}
}

func (cfg *AppConfig) LoadConfig(config_file string) error {
	var err error
	viper.SetConfigFile(config_file)
	err = viper.ReadInConfig() // Find and read the config file
	if err != nil {            // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	var metadata mapstructure.Metadata
	var setDecoderOptsStrict = func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.Metadata = &metadata
	}

	var setDecoderOptsRelaxed = func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = false
		c.Metadata = &metadata
	}
	var srv Server
	err = viper.UnmarshalKey("web_server", &srv, setDecoderOptsRelaxed)
	if err != nil {
		return err
	}

	var monitoring_enabled bool
	err = viper.UnmarshalKey("web_server.status.enable", &monitoring_enabled, setDecoderOptsStrict)
	if err != nil {
		return err
	}
	var path, apiKey string
	if monitoring_enabled {
		err = viper.UnmarshalKey("web_server.status.path", &path, setDecoderOptsStrict)
		if err != nil {
			return err
		}
		err = viper.UnmarshalKey("web_server.status.api_key", &apiKey, setDecoderOptsStrict)
		if err != nil {
			return err
		}
		srv.Monitoring.Enabled = true
		srv.Monitoring.Path = path
		srv.Monitoring.ApiKey = apiKey
	}

	cfg.cf.Srv = srv
	var l Log
	err = viper.UnmarshalKey("log", &l, setDecoderOptsStrict)
	if err != nil {
		return err
	}
	cfg.cf.L = l

	var ac AuthCheck
	err = viper.UnmarshalKey("auth_provider.auth_check", &ac, setDecoderOptsStrict)
	if err != nil {
		return err
	}
	cfg.cf.AuthCheck = &ac

	cfg.cf.AuthProviderType = viper.GetString("auth_provider.type")

	switch cfg.cf.AuthProviderType {
	case "radius":
		return cfg.loadRadiusSettings()
	case "ldap":
		return cfg.loadLDAPSettings()
	default:
		return fmt.Errorf("unsupported auth provider type")
	}
}

func (cfg *AppConfig) loadLDAPSettings() error {
	var metadata mapstructure.Metadata
	var setDecoderOptsStrict = func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.Metadata = &metadata
	}
	authL := AuthLDAP{
		LS: make([]LDAPServer, 0),
	}

	err := viper.UnmarshalKey("auth_provider.ldap", &authL, setDecoderOptsStrict)
	if err != nil {
		return err
	}
	cfg.cf.AuthLDAP = &authL
	return nil
}

func (cfg *AppConfig) loadRadiusSettings() error {
	var metadata mapstructure.Metadata
	authr := AuthRadius{
		RS: make([]RadiusSrv, 0),
	}
	var setDecoderOptsStrict = func(c *mapstructure.DecoderConfig) {
		c.ErrorUnused = true
		c.Metadata = &metadata
	}
	err := viper.UnmarshalKey("auth_provider.radius", &authr, setDecoderOptsStrict)
	if err != nil {
		return err
	}
	cfg.cf.AuthRadius = &authr

	cfg.cf.AuthRadius.nasIpV4Addr = net.ParseIP(cfg.cf.AuthRadius.NASIpV4AddrStr)
	return nil
}

func (cfg *AppConfig) LogConfig() (file, level string) {
	return cfg.cf.L.File, cfg.cf.L.Level
}

func (cfg *AppConfig) SetAppLogger(l globals.AppLogger) {
	cfg.l = l
}
func (cfg *AppConfig) AppLogger() globals.AppLogger {
	return cfg.l
}

func (c *AppConfig) WebSrvConfig() globals.WebSrvConfigProvider {
	return &c.cf.Srv
}

func (c *AppConfig) AuthCheckUser() string {
	return c.cf.AuthCheck.User
}

func (c *AppConfig) AuthCheckPass() string {
	return c.cf.AuthCheck.Pass
}
func (c *AppConfig) AuthCheckInterval() int {
	return c.cf.AuthCheck.IntervalSec
}

func (c *AppConfig) AuthProviderType() string {
	return c.cf.AuthProviderType
}

func (cfg *AppConfig) RadiusServer(i int) (globals.RadiusProvider, error) {
	if i >= len(cfg.cf.AuthRadius.RS) {
		return nil, errors.New("requested value exceeds number of radius servers")
	}
	return &cfg.cf.AuthRadius.RS[i], nil
}

func (cfg *AppConfig) LDAPAuthServer(i int) (globals.LDAPServerProvider, error) {
	if i >= len(cfg.cf.AuthLDAP.LS) {
		return nil, errors.New("requested value exceeds number of ldap servers")
	}
	return &cfg.cf.AuthLDAP.LS[i], nil
}

func (cfg *AppConfig) GetAvailableAuthLDAPServer() (globals.LDAPServerProvider, error) {
	cfg.m.RLock()
	defer cfg.m.RUnlock()
	if len(cfg.availableServers) == 0 {
		return nil, errors.New("No servers available for authentication")
	}

	s, err := cfg.LDAPAuthServer(cfg.availableServers[0])
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (cfg *AppConfig) GetLDAPVerifyCert() bool {
	return cfg.cf.AuthLDAP.VerifyCert
}
func (cfg *AppConfig) GetSearchBase() string {
	return cfg.cf.AuthLDAP.SearchBase
}
func (cfg *AppConfig) GetSearchFilter() string {
	return cfg.cf.AuthLDAP.SearchFilter

}
func (cfg *AppConfig) GetBindUserDN() string {
	return cfg.cf.AuthLDAP.BindDN
}
func (cfg *AppConfig) GetPassword() string {
	return cfg.cf.AuthLDAP.Password
}

func (c *AppConfig) AuthServerName(i int) string {
	if c.cf.AuthProviderType == globals.AuthProviderRadius {
		return c.cf.AuthRadius.RS[i].Name
	}
	if c.cf.AuthProviderType == globals.AuthProviderLDAP {
		return c.cf.AuthLDAP.LS[i].Name
	}
	return ""
}

func (c *AppConfig) NumAuthServers() int {
	if c.cf.AuthProviderType == globals.AuthProviderRadius {
		return len(c.cf.AuthRadius.RS)
	}
	if c.cf.AuthProviderType == globals.AuthProviderLDAP {
		return len(c.cf.AuthLDAP.LS)
	}
	return 0
}

func (c *AppConfig) IsMonitoringEnabled() bool {
	return c.cf.Srv.Monitoring.Enabled
}

func (c *AppConfig) AuthServersStatus() *globals.MonitoringStatusResponse {
	if len(c.availableServers) == 0 {
		return &globals.MonitoringStatusResponse{
			ID:   3,
			Text: globals.StatusText(3),
			Msg:  "None of authentication servers available",
		}
	}
	if len(c.unavailableServers) != 0 {
		return &globals.MonitoringStatusResponse{
			ID:   2,
			Text: globals.StatusText(2),
			Msg:  fmt.Sprintf("%d of %d authentication servers available", len(c.availableServers), len(c.cf.AuthRadius.RS)),
		}
	}
	return &globals.MonitoringStatusResponse{
		ID:   1,
		Text: globals.StatusText(1),
		Msg:  "",
	}
}

func (c *AppConfig) SetAvailableServers(v []int) {
	c.m.Lock()
	defer c.m.Unlock()
	v2 := make([]int, len(v))
	copy(v2, v)
	c.availableServers = v2
}

func (c *AppConfig) SetUnavailableServers(v []int) {
	c.m2.Lock()
	defer c.m2.Unlock()
	v2 := make([]int, len(v))
	copy(v2, v)
	c.unavailableServers = v2
}

func (cfg *AppConfig) GetAvailableRadiusAuthServer() (globals.RadiusProvider, error) {
	//TODO: implement algorithm of choice server
	cfg.m.RLock()
	defer cfg.m.RUnlock()
	if len(cfg.availableServers) == 0 {
		return nil, errors.New("No servers available for authentication")
	}

	s, err := cfg.RadiusServer(cfg.availableServers[0])
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (cfg *AppConfig) AvailableServersIDs() []int {
	numSrv := make([]int, 0, cfg.NumAuthServers())
	for i := 0; i < cfg.NumAuthServers(); i++ {
		numSrv = append(numSrv, i)
	}
	return numSrv
}

func (cfg *AppConfig) GetAuthApiKey() string {
	return cfg.cf.Srv.AuthApiKey
}

func (cfg *AppConfig) GetMonitoringApiKey() string {
	return cfg.cf.Srv.Monitoring.ApiKey
}

func (cfg *AppConfig) GetMonitoringPath() string {
	return cfg.cf.Srv.Monitoring.Path
}
func (cfg *AppConfig) NASID() string {
	return cfg.cf.AuthRadius.NASID
}
func (cfg *AppConfig) NASIpV4Addr() net.IP {
	return cfg.cf.AuthRadius.nasIpV4Addr
}
func (cfg *AppConfig) NASPort() uint32 {
	return uint32(cfg.cf.AuthRadius.NASPort)
}

func (cfg *AppConfig) IsAuthCheckEnabled() bool {
	return cfg.cf.AuthCheck.Enable
}

func (cfg *AppConfig) PrintConfig() {
	cfg.l.Debugf("%#v", cfg)
	cfg.l.Debugf("%#v", cfg.cf.AuthRadius)
	cfg.l.Debugf("%#v", cfg.cf.AuthLDAP)
	cfg.l.Debugf("%#v", cfg.cf.AuthCheck)
	// cfg.l.Debug("%#v", cfg.cf.AuthCheck)

}

func (sc *Server) GetAddress() string {
	return sc.Address
}

func (sc *Server) GetPort() int {
	return sc.Port
}

func (sc *Server) GetAuthApiKey() string {
	return sc.AuthApiKey
}

func (sc *Server) IsMonitoringEnabled() bool {
	return sc.Monitoring.Enabled
}

func (sc *Server) GetMonitoringApiKey() string {
	return sc.Monitoring.ApiKey
}

func (sc *Server) GetMonitoringPath() string {
	return sc.Monitoring.Path
}

func (sc *Server) IsSSLEnabled() bool {
	return sc.HTTPS.Enable
}

func (sc *Server) PrivateKey() string {
	return sc.HTTPS.PrivateKey
}

func (sc *Server) Certificate() string {
	return sc.HTTPS.Certificate
}

func (rc *RadiusSrv) GetAddress() string {
	return rc.Address

}
func (rc *RadiusSrv) GetPort() int {
	return rc.Port
}
func (rc *RadiusSrv) GetSecret() string {
	return rc.Secret
}
func (rc *RadiusSrv) GetProto() string {
	return rc.Proto
}
func (rc *RadiusSrv) GetResponseTimeoutSec() int {
	return rc.ResponseTimeoutSec
}

func (rc *RadiusSrv) GetName() string {
	return rc.Name
}
