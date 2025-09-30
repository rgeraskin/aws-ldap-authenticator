// broker_eks.go
//
// Adds support for EKS tokens (k8s-aws-v1.<b64url>) alongside raw presigned URLs.
// For EKS tokens, the broker injects x-k8s-aws-id when calling STS.

package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/glauth/ldap"
)

var users = make(map[string]*User)

type User struct {
	ARN          string
	Username     string    // 'prefix_john.doe'. Also, it's used as cn in LDAP
	Password     string    // eks_token for http request
	ExpiresAt    time.Time // PasswordTTL
	PrimaryGroup string    // IAM Permission set name. Also, it's used as ou in LDAP
}

// Configuration
type Config struct {
	STSHosts       map[string]bool
	PasswordTTL    time.Duration
	EKSClusterID   string
	PrefixARN      string
	SuffixLDAP     string // ',dc=example,dc=com'
	PortHTTP       string
	PortLDAP       string
	UsernamePrefix string
}

var config Config
var logger *log.Logger

const (
	defaultSTSHost            = "https://sts.amazonaws.com"
	defaultARNPrefix          = "arn:aws:sts::"
	defaultPasswordTTLSeconds = "900"
	defaultPortHTTP           = "8000"
	defaultPortLDAP           = "3893"
)

// Request/Response models
type ExchangeRequest struct {
	EksToken *string `json:"eks_token,omitempty"`
}

type ExchangeResponse struct {
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
}

// STS GetCallerIdentity response structure
type GetCallerIdentityResponse struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		Arn string `xml:"Arn"`
	} `xml:"GetCallerIdentityResult"`
}

func init() {
	// Initialize logger
	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
	})
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func httpError(w http.ResponseWriter, statusCode int, message string, err error) {
	logger.Error(message, "error", err)
	writeErrorResponse(w, statusCode, message)
}

func loadConfig() error {
	logger.Info("Loading configuration")

	// Initialize STS hosts
	stsHostsStr := getEnv("STS_HOSTS", defaultSTSHost)
	config.STSHosts = make(map[string]bool)
	for _, host := range strings.Split(stsHostsStr, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			config.STSHosts[host] = true
		}
	}

	// Parse password TTL
	passwordTTLSeconds, err := strconv.Atoi(
		getEnv("PASSWORD_TTL_SECONDS", defaultPasswordTTLSeconds),
	)
	if err != nil {
		return fmt.Errorf("invalid PASSWORD_TTL_SECONDS: %w", err)
	}
	config.PasswordTTL = time.Duration(passwordTTLSeconds) * time.Second

	config.PrefixARN = getEnv("PREFIX_ARN", defaultARNPrefix)
	config.PortHTTP = getEnv("PORT_HTTP", defaultPortHTTP)
	config.PortLDAP = getEnv("PORT_LDAP", defaultPortLDAP)

	config.SuffixLDAP = os.Getenv("SUFFIX_LDAP")
	config.UsernamePrefix = os.Getenv("PREFIX_USERNAME")
	config.EKSClusterID = os.Getenv("EKS_CLUSTER_ID")
	if config.EKSClusterID == "" {
		return fmt.Errorf("EKS_CLUSTER_ID not configured")
	}

	logger.Info("Configuration loaded successfully",
		"sts_hosts", len(config.STSHosts),
		"password_ttl", config.PasswordTTL,
		"eks_cluster_id", config.EKSClusterID,
		"port_http", config.PortHTTP,
		"port_ldap", config.PortLDAP,
		"prefix_arn", config.PrefixARN,
		"suffix_ldap", config.SuffixLDAP,
		"username_prefix", config.UsernamePrefix)
	return nil
}

func validatePresigned(urlStr string) (*url.URL, url.Values, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %w", err)
	}

	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	logger.Debug("Validating STS origin", "origin", origin)

	if !config.STSHosts[origin] {
		return nil, nil, fmt.Errorf("untrusted STS host: %s", origin)
	}

	qs := parsedURL.Query()
	action := qs.Get("Action")
	if action != "GetCallerIdentity" {
		return nil, nil, fmt.Errorf("action must be GetCallerIdentity, got: %s", action)
	}

	// Must be SigV4 signed
	if qs.Get("X-Amz-Algorithm") == "" || qs.Get("X-Amz-Signature") == "" {
		return nil, nil, fmt.Errorf("missing SigV4 params")
	}

	return parsedURL, qs, nil
}

func callSTS(presignedURL string, extraHeaders map[string]string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", presignedURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	logger.Debug("Calling STS", "url", presignedURL, "headers", extraHeaders)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("STS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("STS verification failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var response GetCallerIdentityResponse
	if err := xml.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse STS response: %w", err)
	}

	if response.Result.Arn == "" {
		return "", fmt.Errorf("ARN not found in response")
	}

	logger.Info("STS call successful", "arn", response.Result.Arn)
	return response.Result.Arn, nil
}

func decodeEKSToken(eksToken string) (string, error) {
	// Expect format: k8s-aws-v1.<base64url of presigned STS URL>
	prefix := "k8s-aws-v1."
	if !strings.HasPrefix(eksToken, prefix) {
		return "", fmt.Errorf("invalid EKS token prefix")
	}

	b64 := eksToken[len(prefix):]
	// Add padding if missing
	padding := strings.Repeat("=", (4-len(b64)%4)%4)
	b64 += padding

	decoded, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("malformed EKS token payload: %w", err)
	}

	logger.Debug("EKS token decoded", "presigned_url", string(decoded))
	return string(decoded), nil
}

func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	writeJSONResponse(w, statusCode, map[string]string{"error": message})
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := "HTTP method not allowed"
		httpError(w, http.StatusMethodNotAllowed, msg, nil)
		return
	}

	var req ExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		msg := "Failed to decode request"
		httpError(w, http.StatusBadRequest, msg, err)
		return
	}

	logger.Info("Received auth request")

	if req.EksToken == nil {
		msg := "eks_token not provided"
		httpError(w, http.StatusBadRequest, msg, nil)
		return
	}

	var extraHeaders map[string]string

	presignedURL, err := decodeEKSToken(*req.EksToken)
	if err != nil {
		msg := "Failed to decode EKS token"
		httpError(w, http.StatusBadRequest, msg, err)
		return
	}

	_, qs, err := validatePresigned(presignedURL)
	if err != nil {
		msg := "Failed to validate presigned URL from EKS token"
		httpError(w, http.StatusBadRequest, msg, err)
		return
	}

	// Ensure x-k8s-aws-id was included in the signed header list
	signedHeaders := strings.ToLower(qs.Get("X-Amz-SignedHeaders"))
	signed := strings.Split(signedHeaders, ";")
	found := false
	for _, header := range signed {
		if strings.TrimSpace(header) == "x-k8s-aws-id" {
			found = true
			break
		}
	}
	if !found {
		msg := "x-k8s-aws-id not in signed headers"
		httpError(w, http.StatusBadRequest, msg, nil)
		return
	}

	extraHeaders = map[string]string{
		"x-k8s-aws-id": config.EKSClusterID,
	}

	arn, err := callSTS(presignedURL, extraHeaders)
	if err != nil {
		msg := "STS verification failed"
		httpError(w, http.StatusUnauthorized, msg, err)
		return
	}

	// Check if ARN matches configured prefix
	if !strings.HasPrefix(arn, config.PrefixARN) {
		msg := "ARN does not match configured prefix"
		httpError(w, http.StatusUnauthorized, msg, nil)
		return
	}

	// Get the username from the ARN
	username := strings.Split(arn, "/")[len(strings.Split(arn, "/"))-1]
	if username == "" {
		msg := "Username not found in ARN"
		httpError(w, http.StatusUnauthorized, msg, nil)
		return
	}

	// Add user to the database
	// remove prefix config.ARNPrefix from arn for primary group
	primaryGroup := strings.TrimPrefix(arn, config.PrefixARN)
	primaryGroup = strings.Split(primaryGroup, "_")[0]
	user := User{
		ARN:          arn,
		Username:     config.UsernamePrefix + username,
		Password:     *req.EksToken,
		ExpiresAt:    time.Now().UTC().Add(config.PasswordTTL),
		PrimaryGroup: primaryGroup,
	}
	bindDNCnOu := fmt.Sprintf("cn=%s,ou=%s%s", user.Username, user.PrimaryGroup, config.SuffixLDAP)
	bindDNCn := fmt.Sprintf("cn=%s%s", user.Username, config.SuffixLDAP)
	bindDNOu := fmt.Sprintf("%s,ou=%s%s", user.Username, user.PrimaryGroup, config.SuffixLDAP)
	bindDN := fmt.Sprintf("%s%s", user.Username, config.SuffixLDAP)
	logger.Info(
		"Adding users",
		"bindDNCnOu",
		bindDNCnOu,
		"bindDNCn",
		bindDNCn,
		"bindDNOu",
		bindDNOu,
		"bindDN",
		bindDN,
	)
	users[bindDNCnOu] = &user
	users[bindDNCn] = &user
	users[bindDNOu] = &user
	users[bindDN] = &user

	// Generate a response
	password := user.Password
	expiresAt := user.ExpiresAt.Format(time.RFC3339)

	response := ExchangeResponse{
		Password:  password,
		ExpiresAt: expiresAt,
	}

	logger.Info("Auth request processed successfully",
		"expires_at", expiresAt)

	writeJSONResponse(w, http.StatusOK, response)
}

type ldapHandler struct {
}

func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	logger.Info("LDAP Bind request", "bindDN", bindDN)
	// check if bindDN is in users and if the password is correct
	user, ok := users[bindDN]
	if ok && bindSimplePw == user.Password {
		logger.Info("LDAP Bind request successful", "bindDN", bindDN)
		return ldap.LDAPResultSuccess, nil

	}
	logger.Info("LDAP Bind request failed", "bindDN", bindDN)
	return ldap.LDAPResultInvalidCredentials, nil
}

func main() {
	// Init log level based on env var
	logLevel := log.InfoLevel
	if os.Getenv("DEBUG") != "" {
		logLevel = log.DebugLevel
	}
	logger.SetLevel(logLevel)

	logger.Info("Starting broker application")

	// Load and validate configuration
	if err := loadConfig(); err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)

	server := &http.Server{
		Addr:         ":" + config.PortHTTP,
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	// Start HTTP server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP Server failed", "error", err)
		}
	}()

	logger.Info("HTTP Server started in background", "port", config.PortHTTP)

	// Your application can continue executing here
	// For example, you could add other services, background tasks, etc.

	// Keep the main goroutine alive (you can replace this with your actual logic)
	s := ldap.NewServer()

	// register Bind and Search function handlers
	handler := ldapHandler{}
	s.BindFunc("", handler)

	// start the server
	listen := "localhost:" + config.PortLDAP
	logger.Info("Starting LDAP server", "listen", listen)
	if err := s.ListenAndServe(listen); err != nil {
		logger.Fatal("LDAP Server failed", "error", err)
	}
}
