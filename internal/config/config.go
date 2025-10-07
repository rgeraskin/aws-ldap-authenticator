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
	ARNPrefixes       map[string]bool
	STSHosts          map[string]bool
	EKSClusterID      string
	LDAPPrefix        string // optional, like "cn=aws_iam_"
	LDAPSuffix        string // optional, like ",dc=evil,dc=corp" - pay attention to the leading comma
	LDAPHost          string
	LDAPPort          string
	LogLevel          string
	STSRequestTimeout time.Duration
}

// Default values
const (
	DefaultSTSHost                  = "https://sts.amazonaws.com"
	DefaultARNPrefix                = "arn:aws:"
	DefaultLDAPHost                 = "0.0.0.0"
	DefaultLDAPPort                 = "3893"
	DefaultLogLevel                 = "info"
	DefaultSTSRequestTimeoutSeconds = "10"
)

// Load loads configuration from environment variables
func Load() (*Config, error) {
	config := &Config{}

	// Parse STS hosts
	config.STSHosts = parseCommas("STS_HOSTS", DefaultSTSHost)

	// Parse ARN prefixes
	config.ARNPrefixes = parseCommas("ARN_PREFIXES", DefaultARNPrefix)

	// Parse durations
	var err error
	if config.STSRequestTimeout, err = parseDuration(
		"REQUEST_TIMEOUT_SECONDS", DefaultSTSRequestTimeoutSeconds,
	); err != nil {
		return nil, err
	}

	// Required and optional fields
	config.EKSClusterID = os.Getenv("EKS_CLUSTER_ID")
	config.LDAPHost = getEnv("LDAP_HOST", DefaultLDAPHost)
	config.LDAPPort = getEnv("LDAP_PORT", DefaultLDAPPort)
	config.LDAPSuffix = os.Getenv("LDAP_SUFFIX")
	config.LDAPPrefix = os.Getenv("LDAP_PREFIX")
	config.LogLevel = getEnv("LOG_LEVEL", DefaultLogLevel)

	return config, nil
}

func parseCommas(envKey, defaultValue string) map[string]bool {
	valuesStr := getEnv(envKey, defaultValue)
	values := make(map[string]bool)
	for _, value := range strings.Split(valuesStr, ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			values[value] = true
		}
	}
	return values
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.EKSClusterID == "" {
		return fmt.Errorf("EKS cluster ID is required")
	}

	if err := validatePort(c.LDAPPort); err != nil {
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
