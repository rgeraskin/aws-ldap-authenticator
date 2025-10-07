package errors

import "github.com/joomcode/errorx"

var (
	// Token
	ErrTokenValidation       = errorx.IllegalArgument.New("token validation failed")
	ErrTokenMissing          = errorx.IllegalArgument.New("EKS token not provided")
	ErrTokenInvalidPrefix    = errorx.IllegalFormat.New("invalid EKS token prefix")
	ErrTokenMalformedPayload = errorx.IllegalFormat.New("malformed token payload")
	ErrTokenInvalidURL       = errorx.IllegalFormat.New("invalid URL")
	// STS
	ErrSTSUntrustedHost = errorx.IllegalArgument.New("untrusted STS host")
	ErrSTSInvalidAction = errorx.IllegalFormat.New(
		"invalid STS action, expected GetCallerIdentity",
	)
	ErrSTSMissingSigV4        = errorx.IllegalArgument.New("missing SigV4 signature in STS request")
	ErrSTSMissingSignedHeader = errorx.IllegalArgument.New("x-k8s-aws-id not in signed headers")
	ErrSTSCreateRequest       = errorx.InitializationFailed.New("failed to create STS request")
	ErrSTSRequestFailed       = errorx.IllegalState.New("STS request failed")
	ErrSTSBadStatus           = errorx.IllegalState.New("STS request returned bad status")
	ErrSTSReadResponse        = errorx.IllegalState.New("failed to read STS response")
	ErrSTSParseResponse       = errorx.IllegalFormat.New("failed to parse STS response")
	ErrSTSNoARN               = errorx.DataUnavailable.New("no ARN in STS response")
	// LDAP bind DN validation
	ErrLDAPInvalidBindDNSuffix = errorx.IllegalArgument.New("invalid bind DN suffix")
	ErrLDAPBindDNArgsNum       = errorx.IllegalArgument.New("invalid number of bind DN attributes")
	ErrLDAPInvalidBindDNCN     = errorx.IllegalArgument.New("invalid bind DN cn")
	ErrLDAPInvalidBindDNOU     = errorx.IllegalArgument.New("invalid bind DN ou")
	// ARN
	ErrARNIsEmpty                  = errorx.IllegalArgument.New("ARN is empty")
	ErrARNPrefixNotAllowed         = errorx.IllegalArgument.New("prefix not allowed")
	ErrARNUsernameNotFound         = errorx.DataUnavailable.New("username not found in ARN")
	ErrARNInvalidFormatColons      = errorx.IllegalFormat.New("invalid number of colons in ARN")
	ErrARNInvalidFormatServiceRole = errorx.IllegalFormat.New(
		"invalid format of service role in ARN",
	)
	ErrARNInvalidFormatAssumedRole = errorx.IllegalFormat.New(
		"invalid format of assumed role in ARN",
	)
	ErrARNInvalidFormatFederatedUser = errorx.IllegalFormat.New(
		"invalid format of federated user in ARN",
	)
	ErrARNInvalidFormatNotAllowed = errorx.UnsupportedOperation.New(
		"ARN format not supported",
	)
)
