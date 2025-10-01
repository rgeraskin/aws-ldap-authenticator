package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/glauth/ldap"

	"aws-ldap-broker/internal/config"
	"aws-ldap-broker/internal/handlers"
	"aws-ldap-broker/internal/services"
)

func main() {
	// Initialize logger
	logger := log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
	})

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}

	if err := cfg.Validate(); err != nil {
		logger.Fatal("Invalid configuration", "error", err)
	}

	// Set log level
	switch cfg.LogLevel {
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "info":
		logger.SetLevel(log.InfoLevel)
	case "warn":
		logger.SetLevel(log.WarnLevel)
	case "error":
		logger.SetLevel(log.ErrorLevel)
	default:
		logger.SetLevel(log.InfoLevel)
	}

	logger.Info("Starting broker application", "config", cfg)

	// Initialize services
	stsService := services.NewSTSService(cfg.STSHosts, cfg.EKSClusterID, cfg.STSTimeout, logger)

	// Initialize handlers
	ldapHandler := handlers.NewLDAPHandler(stsService, cfg, logger)

	// Setup LDAP server
	ldapServer := ldap.NewServer()
	ldapServer.BindFunc("", ldapHandler)

	// Start servers
	go func() {
		listen := cfg.HostLDAP + ":" + cfg.PortLDAP
		logger.Info("Starting LDAP server", "host", cfg.HostLDAP, "port", cfg.PortLDAP)
		if err := ldapServer.ListenAndServe(listen); err != nil {
			logger.Fatal("LDAP server failed", "error", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Shutdown LDAP server gracefully
	logger.Info("Shutting down LDAP server...")
	ldapServer.Close() // This is synchronous and waits for completion

	logger.Info("Servers stopped")
}
