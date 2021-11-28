package websrv

import (
	"auth-service/internal/globals"
	"crypto/tls"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

// var authApiKey string
// var monitoringApiKey string
type ConfigProvider interface {
	GetAuthApiKey() string
	GetMonitoringApiKey() string
	AppLogger() globals.AppLogger
	AuthServersStatus() *globals.MonitoringStatusResponse
	AuthProviderType() string
}

type RouteHandler struct {
	c                ConfigProvider
	authApiKey       string
	monitoringApiKey string
	l                globals.AppLogger
	authClient       globals.AuthClientProvider
}

func NewRouteHandler(c ConfigProvider, authClient globals.AuthClientProvider) *RouteHandler {
	return &RouteHandler{
		c:                c,
		authApiKey:       c.GetAuthApiKey(),
		monitoringApiKey: c.GetMonitoringApiKey(),
		l:                c.AppLogger(),
		authClient:       authClient,
	}
}

func Run(l globals.AppLogger, c globals.WebSrvConfigProvider, r *gin.Engine) *http.Server {
	p := strconv.Itoa(c.GetPort())
	addr := c.GetAddress() + ":" + p
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  90 * time.Second,
		WriteTimeout: 90 * time.Second,
	}

	if c.IsSSLEnabled() {
		srv.TLSConfig = tlsClientSkipVerify
		go func() {
			if err := srv.ListenAndServeTLS(c.Certificate(), c.PrivateKey()); err != nil && err != http.ErrServerClosed {
				l.Error("Unable to start https web server. May wrong path to files?")
				l.Fatal(err)
			}
		}()
	} else {
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				l.Error("Unable to start http web server.")
				l.Fatal(err)
			}
		}()
	}
	l.Info("Auth service started")
	return srv
}

type AuthData struct {
	User     string `json:"u"`
	Password string `json:"p"`
	ClientIP string `json:"client_ip"`
}

const xApiKeyHeader = "X-Api-Key"

func (rh *RouteHandler) AuthenticateUser(c *gin.Context) {
	hv := c.GetHeader(xApiKeyHeader)
	if hv != rh.authApiKey {
		rh.l.Errorf("X-Api-Key is ivalid. Got from client %s", hv)
		c.Status(http.StatusForbidden)
		return
	}
	var authData AuthData
	if err := c.BindJSON(&authData); err != nil {
		rh.l.Error(err)
		c.Status(http.StatusForbidden)
		return
	}
	rh.l.Debugf("Parsed user: %s. Client ip is: %s", authData.User, authData.ClientIP)
	r, netData, err := rh.authClient.AuthenticateUser(authData.User, authData.Password, authData.ClientIP)
	if err != nil {
		rh.l.Debug(err)
		c.Status(http.StatusForbidden)
		return
	}
	if !r {
		c.Status(http.StatusForbidden)
		return
	}
	rh.l.Debugf("Net data for user: %#v", netData)
	if rh.c.AuthProviderType() == globals.AuthProviderRadius {
		c.Header("X-Auth-Provider", "radius")
		c.JSON(http.StatusOK, netData)
		return
	}
	if rh.c.AuthProviderType() == globals.AuthProviderLDAP {
		c.Header("X-Auth-Provider", "ldap")
		c.Status(http.StatusOK)
		return
	}
}

func (rh *RouteHandler) Status(c *gin.Context) {
	hv := c.GetHeader(xApiKeyHeader)
	if hv != rh.monitoringApiKey {
		rh.l.Errorf("X-Api-Key is ivalid. Got from client %s", hv)
		c.Status(http.StatusForbidden)
		return
	}
	resp := rh.c.AuthServersStatus()
	c.JSON(http.StatusOK, resp)
}
