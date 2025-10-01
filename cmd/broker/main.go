package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/glauth/ldap"

	"broker/internal/config"
	"broker/internal/handlers"
	"broker/internal/middleware"
	"broker/internal/services"
	"broker/internal/storage"
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
	userStore := storage.NewUserStore(cfg.CleanupInterval)
	stsService := services.NewSTSService(cfg.STSHosts, cfg.EKSClusterID, cfg.STSTimeout, logger)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(stsService, userStore, cfg, logger)
	ldapHandler := handlers.NewLDAPHandler(userStore, logger)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.Handle("/auth", authHandler)

	// Wire middlewares: recovery always, logging only in debug
	var httpHandler http.Handler = mux
	if cfg.LogLevel == "debug" {
		httpHandler = middleware.LoggingMiddleware(logger)(httpHandler)
	}
	httpHandler = middleware.RecoveryMiddleware(logger)(httpHandler)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	httpServer := &http.Server{
		Addr:         cfg.HostHTTP + ":" + cfg.PortHTTP,
		Handler:      httpHandler,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	}

	// Setup LDAP server
	ldapServer := ldap.NewServer()
	ldapServer.BindFunc("", ldapHandler)

	// Start servers
	go func() {
		logger.Info("Starting HTTP server", "host", cfg.HostHTTP, "port", cfg.PortHTTP)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", "error", err)
		}
	}()

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

	logger.Info("Shutting down servers...")
	logger.Info("Shutting down HTTP server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown failed", "error", err)
	}

	// Shutdown LDAP server gracefully
	logger.Info("Shutting down LDAP server...")
	ldapServer.Close() // This is synchronous and waits for completion

	logger.Info("Servers stopped")
}
