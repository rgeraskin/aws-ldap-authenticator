package handlers

import (
	"context"
	"net"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/glauth/ldap"

	"github.com/rgeraskin/aws-ldap-authenticator/internal/config"
	apperrors "github.com/rgeraskin/aws-ldap-authenticator/internal/errors"
	"github.com/rgeraskin/aws-ldap-authenticator/internal/services"
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

	reportError := func(err error) (ldap.LDAPResultCode, error) {
		h.logger.Error("LDAP bind failed", "err", err, "bindDN", bindDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Check if password is empty
	if bindPw == "" {
		return reportError(apperrors.ErrTokenMissing)
	}

	// From the ARN we can extract only the cn (username) and group (ou).
	// To validate the remaining parts of the bindDN, ensure the configured
	// suffix equals the suffix of the bindDN.

	// Example input bindDN: cn=aws_iam_john.doe,ou=supportl1,dc=evil,dc=corp
	// To successfully LDAP bind, configure the app so that
	// LDAP_SUFFIX is ",dc=evil,dc=corp". It can be any string.
	// Later we'll trim the suffix from the bindDN and continue validation.

	if h.config.LDAPSuffix != "" && !strings.HasSuffix(bindDN, h.config.LDAPSuffix) {
		return reportError(apperrors.ErrLDAPInvalidBindDNSuffix)
	}

	// Now validate the EKS token
	// If the token is not expired, AWS will return the ARN.
	ctx, cancel := context.WithTimeout(context.Background(), h.config.STSRequestTimeout)
	defer cancel()
	arn, err := h.stsService.ValidateEKSToken(ctx, bindPw)
	if err != nil {
		// preserve underlying error in logs while returning consistent LDAP code
		h.logger.Error("EKS token validation failed", "err", err)
		return reportError(apperrors.ErrTokenValidation)
	}

	// Check if ARN matches configured prefix
	arnMatched := false
	for prefix := range h.config.ARNPrefixes {
		if strings.HasPrefix(arn, prefix) {
			arnMatched = true
			h.logger.Debug("ARN matched prefix", "prefix", prefix)
			break
		}
	}
	if !arnMatched {
		return reportError(apperrors.ErrARNPrefixNotAllowed)
	}

	// Extract cn (username) and group (ou) from ARN
	username, group, err := h.extractFromARN(arn)
	if err != nil {
		return reportError(err)
	}
	if username == "" {
		return reportError(apperrors.ErrARNUsernameNotFound)
	}
	h.logger.Debug("LDAP Bind username and group", "username", username, "group", group)

	// Now validate the username (cn) and group (aka ou)
	// The remaining parts of the bindDN after removing the suffix are cn and ou.
	// LDAPSuffix may be empty, but it doesn't matter in this case.
	dn := strings.TrimSuffix(bindDN, h.config.LDAPSuffix)

	// cn is required and should be equal to the username extracted from the ARN.
	// ou is optional, but if present should be equal to the group extracted from the ARN.
	// No other parts of the bindDN are allowed.
	attrs := strings.Split(dn, ",")
	h.logger.Debug("LDAP Bind attributes", "attrs", attrs)
	if len(attrs) > 2 {
		return reportError(apperrors.ErrLDAPBindDNArgsNum)
	}

	// Check cn: expect the first RDN to equal LDAPPrefix + username, exactly
	if attrs[0] != h.config.LDAPPrefix+username {
		return reportError(apperrors.ErrLDAPInvalidBindDNCN)
	}

	// Check ou (if present): expect exact match "ou=" + group
	if len(attrs) == 2 {
		if attrs[1] != "ou="+group {
			return reportError(apperrors.ErrLDAPInvalidBindDNOU)
		}
	} else {
		h.logger.Debug("No ou attribute found in bindDN", "bindDN", bindDN)
	}

	h.logger.Info("LDAP Bind successful", "bindDN", bindDN)
	return ldap.LDAPResultSuccess, nil
}

func (h *LDAPHandler) extractFromARN(arn string) (string, string, error) {
	if arn == "" {
		return "", "", apperrors.ErrARNIsEmpty
	}

	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", "", apperrors.ErrARNInvalidFormatColons
	}

	service := parts[2]  // iam or sts
	resource := parts[5] // everything after the 5th colon

	// Possible ARN formats

	// Root User: Using the AWS root account credentials (not advised)
	// Format: arn:aws:iam::<account-id>:root
	// Example: arn:aws:iam::123456789012:root
	// cn - root, ou - empty
	if service == "iam" && resource == "root" {
		return "root", "", nil
	}

	// IAM User: Logged in with long-term access keys of an IAM user
	// Format: arn:aws:iam::<account-id>:user/<user-name>
	// Example: arn:aws:iam::123456789012:user/jane.doe
	// cn - jane.doe, ou - empty
	if service == "iam" && strings.HasPrefix(resource, "user/") {
		segs := strings.Split(resource, "/")
		if len(segs) >= 2 {
			return segs[len(segs)-1], "", nil
		}
		return "", "", apperrors.ErrARNUsernameNotFound
	}

	// IAM Role (Assumed): When calling with temporary creds from sts:AssumeRole
	// or Cross-Account Role: When assuming a role in another AWS account
	// Format: arn:aws:sts::<account-id>:assumed-role/<role-name>/<session-name>
	// Example: arn:aws:sts::123456789012:assumed-role/AdminRole/Alice
	// cn - Alice, ou - AdminRole
	if service == "sts" && strings.HasPrefix(resource, "assumed-role/") {
		segs := strings.Split(resource, "/")
		if len(segs) >= 3 {
			roleName := segs[1]
			sessionName := segs[2]
			return sessionName, roleName, nil
		}
		return "", "", apperrors.ErrARNInvalidFormatAssumedRole
	}

	// Federated User: Temporary creds from SAML, OIDC, or custom federation
	// Format: arn:aws:sts::<account-id>:federated-user/<user-name>
	// Example: arn:aws:sts::123456789012:federated-user/GoogleOIDC:jane
	// cn - jane, ou - empty
	if service == "sts" && strings.HasPrefix(resource, "federated-user/") {
		segs := strings.Split(resource, "/")
		if len(segs) >= 2 {
			return segs[len(segs)-1], "", nil
		}
		return "", "", apperrors.ErrARNInvalidFormatFederatedUser
	}

	// Service-Linked Role: When AWS services assume roles on your behalf
	// Format: arn:aws:iam::<account-id>:role/aws-service-role/<service-name>.amazonaws.com/<role-name>
	// Example: arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling
	// cn - AWSServiceRoleForAutoScaling, ou - autoscaling.amazonaws.com
	if service == "iam" && strings.HasPrefix(resource, "role/aws-service-role/") {
		segs := strings.Split(resource, "/")
		if len(segs) >= 4 {
			serviceHost := segs[2] // e.g. autoscaling.amazonaws.com
			roleName := segs[3]
			return roleName, serviceHost, nil
		}
		return "", "", apperrors.ErrARNInvalidFormatServiceRole
	}

	// No other formats are allowed, so return error
	return "", "", apperrors.ErrARNInvalidFormatNotAllowed
}
