package handlers

import (
	"net"

	"github.com/charmbracelet/log"
	"github.com/glauth/ldap"

	"broker/internal/storage"
)

// LDAPHandler handles LDAP operations
type LDAPHandler struct {
	userStore *storage.UserStore
	logger    *log.Logger
}

// NewLDAPHandler creates a new LDAP handler
func NewLDAPHandler(userStore *storage.UserStore, logger *log.Logger) *LDAPHandler {
	return &LDAPHandler{
		userStore: userStore,
		logger:    logger,
	}
}

// Bind handles LDAP bind requests
func (h *LDAPHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	h.logger.Info("LDAP Bind request", "bindDN", bindDN, "remote_addr", conn.RemoteAddr())

	user, exists := h.userStore.Get(bindDN)
	if !exists {
		h.logger.Warn("LDAP Bind failed: user not found", "bindDN", bindDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	if bindSimplePw != user.Password {
		h.logger.Warn("LDAP Bind failed: invalid password", "bindDN", bindDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.logger.Info("LDAP Bind successful", "bindDN", bindDN, "username", user.Username)
	return ldap.LDAPResultSuccess, nil
}
