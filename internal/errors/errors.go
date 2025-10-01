package errors

const (
	ErrMissingToken           = "EKS token not provided"
	ErrSTSVerification        = "STS verification failed"
	ErrInvalidTokenPrefix     = "invalid EKS token prefix"
	ErrMalformedTokenPayload  = "malformed token payload"
	ErrInvalidURL             = "invalid URL"
	ErrUntrustedSTSHost       = "untrusted STS host"
	ErrInvalidSTSAction       = "invalid STS action, expected GetCallerIdentity"
	ErrMissingSTSSigV4        = "missing SigV4 signature in STS request"
	ErrMissingSTSSignedHeader = "x-k8s-aws-id not in signed headers"
	ErrSTSCreateRequest       = "failed to create STS request"
	ErrSTSRequestFailed       = "STS request failed"
	ErrSTSBadStatus           = "STS request returned bad status"
	ErrSTSReadResponse        = "failed to read STS response"
	ErrSTSParseResponse       = "failed to parse STS response"
	ErrSTSNoARN               = "no ARN in STS response"
	ErrInvalidBindDN          = "invalid bind DN"
)
