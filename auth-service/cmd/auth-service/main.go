package main

import (
	"auth-service/internal/applog"
	"auth-service/internal/authcheck"
	"auth-service/internal/config"
	"auth-service/internal/globals"
	"auth-service/internal/ldapc"
	"auth-service/internal/radiusc"
	"auth-service/internal/websrv"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	config_file := flag.String("config", "", "Full path to config file")
	flag.Parse()
	if len(*config_file) <= 1 {
		fmt.Println("Config file command line parameter must be present. Run with option -h for help")
		return
	}
	acfg := config.NewConfig()
	if err := acfg.LoadConfig(*config_file); err != nil {
		log.Fatal(err)
		return
	}
	p, lvl := acfg.LogConfig()
	logger := applog.NewLogger(p, lvl)
	acfg.SetAppLogger(logger)
	run(acfg)
}

func run(acfg *config.AppConfig) {
	authClient := authClient(acfg)
	srv := acfg.AvailableServersIDs()
	acfg.SetAvailableServers(srv)
	acfg.PrintConfig() //only if logging level is debug
	if acfg.IsAuthCheckEnabled() {
		go authcheck.StartAuthCheckTask(acfg, authClient)
	}
	rh := websrv.NewRouteHandler(acfg, authClient)
	r := setupRoutes(acfg, rh)
	httpSrv := websrv.Run(acfg.AppLogger(), acfg.WebSrvConfig(), r)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		acfg.AppLogger().Fatalf("Server shutdown failed: %s", err)
	}
	acfg.AppLogger().Info("Auth service stopped")
}

func authClient(c *config.AppConfig) globals.AuthClientProvider {
	switch c.AuthProviderType() {
	case globals.AuthProviderRadius:
		return radiusc.NewClient(c)
	case globals.AuthProviderLDAP:
		return ldapc.NewClient(c)
	}
	return nil
}

func setupRoutes(c *config.AppConfig, rh *websrv.RouteHandler) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.POST("/auth", rh.AuthenticateUser)
	if c.IsMonitoringEnabled() {
		c.AppLogger().Debugf("Monitoring path is %s", c.GetMonitoringPath())
		c.AppLogger().Debugf("Monitoring api key is %s", c.GetMonitoringApiKey())
		r.GET(c.GetMonitoringPath(), rh.Status)
	}
	return r
}
