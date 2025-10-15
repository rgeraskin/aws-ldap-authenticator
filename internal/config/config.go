package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

var (
	ErrPortInvalid          = errors.New("port must be between 1 and 65535")
	ErrEKSClusterIDRequired = errors.New("EKS cluster ID is required")
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
func Load() (config *Config, err error) {
	defer err2.Handle(&err)

	config = &Config{}

	// Parse STS hosts
	config.STSHosts = parseCommas("STS_HOSTS", DefaultSTSHost)

	// Parse ARN prefixes
	config.ARNPrefixes = parseCommas("ARN_PREFIXES", DefaultARNPrefix)

	// Parse durations
	config.STSRequestTimeout = try.To1(
		parseDuration(
			"REQUEST_TIMEOUT_SECONDS", DefaultSTSRequestTimeoutSeconds,
		))

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
func (c *Config) Validate() (err error) {
	defer err2.Handle(&err)

	if c.EKSClusterID == "" {
		return ErrEKSClusterIDRequired
	}

	return validatePort(c.LDAPPort)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func validatePort(port string) (err error) {
	defer err2.Handle(&err)

	p := try.To1(strconv.Atoi(port))
	if p < 1 || p > 65535 {
		return ErrPortInvalid
	}
	return nil
}

func parseDuration(envKey, defaultValue string) (_ time.Duration, err error) {
	defer err2.Handle(&err)

	seconds := try.To1(strconv.Atoi(getEnv(envKey, defaultValue)))
	return time.Duration(seconds) * time.Second, nil
}
