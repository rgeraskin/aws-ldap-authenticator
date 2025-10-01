package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration
type Config struct {
	STSHosts         map[string]bool
	PasswordTTL      time.Duration
	EKSClusterID     string
	PrefixARN        string
	SuffixLDAP       string // ",dc=glauth,dc=com" - pay attention to the leading comma
	HostHTTP         string
	PortHTTP         string
	HostLDAP         string
	PortLDAP         string
	PrefixUsername   string
	LogLevel         string
	RequestTimeout   time.Duration
	HTTPReadTimeout  time.Duration
	HTTPWriteTimeout time.Duration
	HTTPIdleTimeout  time.Duration
	STSTimeout       time.Duration
	CleanupInterval  time.Duration
}

// Default values
const (
	DefaultSTSHost                 = "https://sts.amazonaws.com"
	DefaultARNPrefix               = "arn:aws:sts::"
	DefaultPasswordTTLSeconds      = "900" // 15 minutes
	DefaultHostHTTP                = "0.0.0.0"
	DefaultPortHTTP                = "8000"
	DefaultHostLDAP                = "0.0.0.0"
	DefaultPortLDAP                = "3893"
	DefaultLogLevel                = "info"
	DefaultRequestTimeoutSeconds   = "30"
	DefaultHTTPReadTimeoutSeconds  = "10"
	DefaultHTTPWriteTimeoutSeconds = "10"
	DefaultHTTPIdleTimeoutSeconds  = "60"
	DefaultSTSTimeoutSeconds       = "10"
	DefaultCleanupIntervalSeconds  = "60"
)

// Load loads configuration from environment variables
func Load() (*Config, error) {
	config := &Config{}

	// Parse STS hosts
	stsHostsStr := getEnv("STS_HOSTS", DefaultSTSHost)
	config.STSHosts = make(map[string]bool)
	for _, host := range strings.Split(stsHostsStr, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			config.STSHosts[host] = true
		}
	}

	// Parse durations
	passwordTTLSeconds, err := strconv.Atoi(
		getEnv("PASSWORD_TTL_SECONDS", DefaultPasswordTTLSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid PASSWORD_TTL_SECONDS: %w", err)
	}
	config.PasswordTTL = time.Duration(passwordTTLSeconds) * time.Second

	requestTimeoutSeconds, err := strconv.Atoi(
		getEnv("REQUEST_TIMEOUT_SECONDS", DefaultRequestTimeoutSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid REQUEST_TIMEOUT_SECONDS: %w", err)
	}
	config.RequestTimeout = time.Duration(requestTimeoutSeconds) * time.Second

	httpReadTimeoutSeconds, err := strconv.Atoi(
		getEnv("HTTP_READ_TIMEOUT_SECONDS", DefaultHTTPReadTimeoutSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP_READ_TIMEOUT_SECONDS: %w", err)
	}
	config.HTTPReadTimeout = time.Duration(httpReadTimeoutSeconds) * time.Second

	httpWriteTimeoutSeconds, err := strconv.Atoi(
		getEnv("HTTP_WRITE_TIMEOUT_SECONDS", DefaultHTTPWriteTimeoutSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP_WRITE_TIMEOUT_SECONDS: %w", err)
	}
	config.HTTPWriteTimeout = time.Duration(httpWriteTimeoutSeconds) * time.Second

	httpIdleTimeoutSeconds, err := strconv.Atoi(
		getEnv("HTTP_IDLE_TIMEOUT_SECONDS", DefaultHTTPIdleTimeoutSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP_IDLE_TIMEOUT_SECONDS: %w", err)
	}
	config.HTTPIdleTimeout = time.Duration(httpIdleTimeoutSeconds) * time.Second

	stsTimeoutSeconds, err := strconv.Atoi(getEnv("STS_TIMEOUT_SECONDS", DefaultSTSTimeoutSeconds))
	if err != nil {
		return nil, fmt.Errorf("invalid STS_TIMEOUT_SECONDS: %w", err)
	}
	config.STSTimeout = time.Duration(stsTimeoutSeconds) * time.Second

	cleanupIntervalSeconds, err := strconv.Atoi(
		getEnv("CLEANUP_INTERVAL_SECONDS", DefaultCleanupIntervalSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid CLEANUP_INTERVAL_SECONDS: %w", err)
	}
	config.CleanupInterval = time.Duration(cleanupIntervalSeconds) * time.Second

	// Required and optional fields
	config.EKSClusterID = os.Getenv("EKS_CLUSTER_ID")
	config.PrefixARN = getEnv("PREFIX_ARN", DefaultARNPrefix)
	config.HostHTTP = getEnv("HOST_HTTP", DefaultHostHTTP)
	config.PortHTTP = getEnv("PORT_HTTP", DefaultPortHTTP)
	config.HostLDAP = getEnv("HOST_LDAP", DefaultHostLDAP)
	config.PortLDAP = getEnv("PORT_LDAP", DefaultPortLDAP)
	config.SuffixLDAP = os.Getenv("SUFFIX_LDAP")
	config.PrefixUsername = os.Getenv("PREFIX_USERNAME")
	config.LogLevel = getEnv("LOG_LEVEL", DefaultLogLevel)

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.PasswordTTL <= 0 {
		return fmt.Errorf("password TTL must be positive")
	}

	if c.EKSClusterID == "" {
		return fmt.Errorf("EKS cluster ID is required")
	}

	// Validate ports
	if err := validatePort(c.PortHTTP); err != nil {
		return fmt.Errorf("invalid HTTP port: %w", err)
	}

	if err := validatePort(c.PortLDAP); err != nil {
		return fmt.Errorf("invalid LDAP port: %w", err)
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func validatePort(port string) error {
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be a number: %w", err)
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}
