package errors

import (
	"fmt"
	"net/http"
)

// AppError represents an application error with HTTP status code
type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// Predefined errors
var (
	ErrInvalidMethod = &AppError{
		Code:    http.StatusMethodNotAllowed,
		Message: "Method not allowed",
	}
	ErrInvalidRequest = &AppError{
		Code:    http.StatusBadRequest,
		Message: "Failed to decode request",
	}
	ErrMissingToken    = &AppError{Code: http.StatusBadRequest, Message: "EKS token not provided"}
	ErrSTSVerification = &AppError{
		Code:    http.StatusUnauthorized,
		Message: "STS verification failed",
	}
	ErrInvalidARN       = &AppError{Code: http.StatusUnauthorized, Message: "Invalid ARN"}
	ErrUsernameNotFound = &AppError{
		Code:    http.StatusUnauthorized,
		Message: "Username not found in ARN",
	}
)

// Domain-specific errors (for services)
var (
	ErrInvalidTokenPrefix     = fmt.Errorf("invalid EKS token prefix")
	ErrMalformedTokenPayload  = fmt.Errorf("malformed EKS token payload")
	ErrInvalidURL             = fmt.Errorf("invalid URL")
	ErrUntrustedSTSHost       = fmt.Errorf("untrusted STS host")
	ErrInvalidSTSAction       = fmt.Errorf("action must be GetCallerIdentity")
	ErrMissingSTSSigV4        = fmt.Errorf("missing SigV4 parameters")
	ErrMissingSTSSignedHeader = fmt.Errorf("x-k8s-aws-id not in signed headers")
	ErrSTSRequestFailed       = fmt.Errorf("STS request failed")
	ErrSTSBadStatus           = fmt.Errorf("STS verification failed with bad status")
	ErrSTSReadResponse        = fmt.Errorf("failed to read STS response")
	ErrSTSParseResponse       = fmt.Errorf("failed to parse STS response")
	ErrSTSNoARN               = fmt.Errorf("ARN not found in response")
	ErrSTSCreateRequest       = fmt.Errorf("failed to create STS request")
)

// New creates a new AppError
func New(code int, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code int, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
