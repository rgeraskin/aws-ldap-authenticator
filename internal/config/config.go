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
	STSHosts       map[string]bool
	EKSClusterID   string
	PrefixARN      string
	SuffixLDAP     string // optional, ",dc=glauth,dc=com" - pay attention to the leading comma
	HostLDAP       string
	PortLDAP       string
	PrefixUsername string
	LogLevel       string
	RequestTimeout time.Duration
	STSTimeout     time.Duration
}

// Default values
const (
	DefaultSTSHost               = "https://sts.amazonaws.com"
	DefaultARNPrefix             = "arn:aws:sts::"
	DefaultHostLDAP              = "0.0.0.0"
	DefaultPortLDAP              = "3893"
	DefaultLogLevel              = "info"
	DefaultRequestTimeoutSeconds = "30"
	DefaultSTSTimeoutSeconds     = "10"
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
	var err error
	if config.RequestTimeout, err = parseDuration(
		"REQUEST_TIMEOUT_SECONDS", DefaultRequestTimeoutSeconds,
	); err != nil {
		return nil, err
	}
	if config.STSTimeout, err = parseDuration(
		"STS_TIMEOUT_SECONDS", DefaultSTSTimeoutSeconds,
	); err != nil {
		return nil, err
	}

	// Required and optional fields
	config.EKSClusterID = os.Getenv("EKS_CLUSTER_ID")
	config.PrefixARN = getEnv("PREFIX_ARN", DefaultARNPrefix)
	config.HostLDAP = getEnv("HOST_LDAP", DefaultHostLDAP)
	config.PortLDAP = getEnv("PORT_LDAP", DefaultPortLDAP)
	config.SuffixLDAP = os.Getenv("SUFFIX_LDAP")
	config.PrefixUsername = os.Getenv("PREFIX_USERNAME")
	config.LogLevel = getEnv("LOG_LEVEL", DefaultLogLevel)

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {

	if c.EKSClusterID == "" {
		return fmt.Errorf("EKS cluster ID is required")
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

func parseDuration(envKey, defaultValue string) (time.Duration, error) {
	seconds, err := strconv.Atoi(getEnv(envKey, defaultValue))
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", envKey, err)
	}
	return time.Duration(seconds) * time.Second, nil
}
