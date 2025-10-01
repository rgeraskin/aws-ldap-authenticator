package handlers

import (
	"context"
	"net"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/glauth/ldap"

	"aws-ldap-broker/internal/config"
	"aws-ldap-broker/internal/errors"
	"aws-ldap-broker/internal/services"
)

// LDAPHandler handles LDAP operations
type LDAPHandler struct {
	stsService *services.STSService
	config     *config.Config
	logger     *log.Logger
}

// NewLDAPHandler creates a new LDAP handler
func NewLDAPHandler(
	stsService *services.STSService,
	config *config.Config,
	logger *log.Logger,
) *LDAPHandler {
	return &LDAPHandler{
		stsService: stsService,
		config:     config,
		logger:     logger,
	}
}

// Bind handles LDAP bind requests
func (h *LDAPHandler) Bind(
	bindDN, bindPw string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.logger.Info("LDAP Bind request", "bindDN", bindDN, "remote_addr", conn.RemoteAddr())

	if bindPw == "" {
		h.logger.Error(errors.ErrMissingToken)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Check if bindDN matches configured prefix and suffix
	if !strings.HasPrefix(bindDN, "cn="+h.config.PrefixUsername) ||
		!strings.HasSuffix(bindDN, h.config.SuffixLDAP) {
		h.logger.Error(errors.ErrInvalidBindDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.config.RequestTimeout)
	defer cancel()
	arn, err := h.stsService.ValidateEKSToken(ctx, bindPw)
	if err != nil {
		h.logger.Error(errors.ErrSTSVerification)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Check if ARN matches configured prefix
	if !strings.HasPrefix(arn, h.config.PrefixARN) {
		h.logger.Error(errors.ErrInvalidTokenPrefix)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.logger.Info("LDAP Bind successful", "bindDN", bindDN)
	return ldap.LDAPResultSuccess, nil
}
