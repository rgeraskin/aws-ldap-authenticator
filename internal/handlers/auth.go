package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/log"

	"broker/internal/config"
	"broker/internal/errors"
	"broker/internal/services"
	"broker/internal/storage"
)

// AuthHandler handles authentication requests
type AuthHandler struct {
	stsService *services.STSService
	userStore  *storage.UserStore
	config     *config.Config
	logger     *log.Logger
}

// ExchangeRequest represents the auth request payload
type ExchangeRequest struct {
	EksToken *string `json:"eks_token,omitempty"`
}

// ExchangeResponse represents the auth response payload
type ExchangeResponse struct {
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	stsService *services.STSService,
	userStore *storage.UserStore,
	config *config.Config,
	logger *log.Logger,
) *AuthHandler {
	return &AuthHandler{
		stsService: stsService,
		userStore:  userStore,
		config:     config,
		logger:     logger,
	}
}

// ServeHTTP handles HTTP requests
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.config.RequestTimeout)
	defer cancel()

	if r.Method != http.MethodPost {
		h.writeError(w, errors.ErrInvalidMethod)
		return
	}

	// Enforce small body and JSON content type
	const maxBodySize = 32 * 1024 // 32KB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer r.Body.Close()
	if ct := r.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(strings.ToLower(ct), "application/json") {
		h.writeError(w, errors.ErrInvalidRequest)
		return
	}

	var req ExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, errors.ErrInvalidRequest)
		return
	}

	h.logger.Info("Received auth request")

	if req.EksToken == nil {
		h.writeError(w, errors.ErrMissingToken)
		return
	}
	eksToken := strings.TrimSpace(*req.EksToken)
	if eksToken == "" {
		h.writeError(w, errors.ErrMissingToken)
		return
	}

	arn, err := h.stsService.ValidateEKSToken(ctx, eksToken)
	if err != nil {
		h.writeError(w, errors.ErrSTSVerification)
		return
	}

	// Check if ARN matches configured prefix
	if !strings.HasPrefix(arn, h.config.PrefixARN) {
		h.writeError(w, errors.ErrInvalidARN)
		return
	}

	// Extract username from ARN
	username := h.extractUsernameFromARN(arn)
	if username == "" {
		h.writeError(w, errors.ErrUsernameNotFound)
		return
	}

	// Create user
	user := &storage.User{
		ARN:          arn,
		Username:     h.config.PrefixUsername + username,
		Password:     eksToken,
		ExpiresAt:    time.Now().UTC().Add(h.config.PasswordTTL),
		PrimaryGroup: h.extractPrimaryGroup(arn),
	}

	// Store user with multiple bind DN variations
	bindDNs := h.generateBindDNs(user)
	h.userStore.Set(bindDNs, user)

	h.logger.Info("User authenticated successfully",
		"username", user.Username,
		"primary_group", user.PrimaryGroup,
		"expires_at", user.ExpiresAt)

	response := ExchangeResponse{
		Password:  user.Password,
		ExpiresAt: user.ExpiresAt.Format(time.RFC3339),
	}

	h.writeJSON(w, http.StatusOK, response)
}

func (h *AuthHandler) extractUsernameFromARN(arn string) string {
	parts := strings.Split(arn, "/")
	if parts[len(parts)-1] == "" {
		return ""
	}
	return parts[len(parts)-1]
}

func (h *AuthHandler) extractPrimaryGroup(arn string) string {
	// Expected formats include:
	// - arn:aws:sts::<acct>:assumed-role/AWSReservedSSO_<RoleName>_<hash>/<username>
	// - arn:aws:iam::<acct>:user/<username> (fallback)
	// We want PrimaryGroup == RoleName for AWSReservedSSO roles.

	// Otherwise, return empty string to omit ou.
	if !strings.Contains(arn, "assumed-role") {
		return ""
	}

	// Assume that last part of ARN is the username
	parts := strings.Split(arn, "/")
	if len(parts) < 2 {
		// Should not happen
		return ""
	}

	// assumedRole is like "AWSReservedSSO_<RoleName>_<hash>"
	assumedRole := parts[len(parts)-2]
	// Now we have something like "AWSReservedSSO_<RoleName>_<hash>"
	roleParts := strings.Split(assumedRole, "_")
	if len(roleParts) < 3 || roleParts[0] != "AWSReservedSSO" {
		// Don't know is it possible, but anyway
		return ""
	}
	// Now join parts in the middle with "_"
	roleName := strings.Join(roleParts[1:len(roleParts)-1], "_")
	return roleName
}

func (h *AuthHandler) generateBindDNs(user *storage.User) []string {
	var bindDNs []string

	// If PrimaryGroup present, also include ou variant.
	if user.PrimaryGroup != "" {
		bindDNs = append(bindDNs,
			fmt.Sprintf("cn=%s,ou=%s%s", user.Username, user.PrimaryGroup, h.config.SuffixLDAP),
		)
	}
	bindDNs = append(bindDNs,
		fmt.Sprintf("cn=%s%s", user.Username, h.config.SuffixLDAP),
	)

	return bindDNs
}

func (h *AuthHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

func (h *AuthHandler) writeError(w http.ResponseWriter, appErr *errors.AppError) {
	h.logger.Error("Request failed", "error", appErr.Error(), "code", appErr.Code)
	h.writeJSON(w, appErr.Code, map[string]string{"error": appErr.Message})
}
