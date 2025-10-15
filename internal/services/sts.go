package services

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

var (
	ErrTokenInvalidPrefix    = errors.New("invalid EKS token prefix")
	ErrTokenMalformedPayload = errors.New("malformed token payload")
	ErrTokenInvalidURL       = errors.New("invalid URL")
	// STS
	ErrSTSUntrustedHost = errors.New("untrusted STS host")
	ErrSTSInvalidAction = errors.New(
		"invalid STS action, expected GetCallerIdentity",
	)
	ErrSTSMissingSigV4        = errors.New("missing SigV4 signature in STS request")
	ErrSTSMissingSignedHeader = errors.New("x-k8s-aws-id not in signed headers")
	ErrSTSCreateRequest       = errors.New("failed to create STS request")
	ErrSTSRequestFailed       = errors.New("STS request failed")
	ErrSTSBadStatus           = errors.New("STS request returned bad status")
	ErrSTSReadResponse        = errors.New("failed to read STS response")
	ErrSTSParseResponse       = errors.New("failed to parse STS response")
	ErrSTSNoARN               = errors.New("no ARN in STS response")
)

// STS handles STS operations
type Sts struct {
	client    *http.Client
	stsHosts  map[string]bool
	clusterID string
	logger    *log.Logger
}

// GetCallerIdentityResponse represents STS response
type GetCallerIdentityResponse struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		Arn string `xml:"Arn"`
	} `xml:"GetCallerIdentityResult"`
}

// NewSTS creates a new STS service
func NewSTS(
	stsHosts map[string]bool,
	clusterID string,
	timeout time.Duration,
	logger *log.Logger,
) *Sts {
	return &Sts{
		client: &http.Client{
			Timeout: 0, // rely on context deadlines from callers
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		stsHosts:  stsHosts,
		clusterID: clusterID,
		logger:    logger,
	}
}

// DecodeEksToken decodes an EKS token to get the presigned URL
func (s *Sts) DecodeEksToken(eksToken string) (_ string, err error) {
	defer err2.Handle(&err)

	const prefix = "k8s-aws-v1."
	if !strings.HasPrefix(eksToken, prefix) {
		return "", ErrTokenInvalidPrefix
	}

	b64 := eksToken[len(prefix):]
	decoded := try.To1(base64.RawURLEncoding.DecodeString(b64))

	return string(decoded), nil
}

// ValidatePresignedURL validates a presigned STS URL
func (s *Sts) ValidatePresignedURL(urlStr string) (_ *url.URL, _ url.Values, err error) {
	defer err2.Handle(&err)

	parsedURL := try.To1(url.Parse(urlStr))

	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	if !s.stsHosts[origin] {
		return nil, nil, fmt.Errorf("%w: %s", ErrSTSUntrustedHost, origin)
	}

	qs := parsedURL.Query()
	action := qs.Get("Action")
	if action != "GetCallerIdentity" {
		return nil, nil, fmt.Errorf("%w: %s", ErrSTSInvalidAction, action)
	}

	// Must be SigV4 signed
	if qs.Get("X-Amz-Algorithm") == "" || qs.Get("X-Amz-Signature") == "" {
		return nil, nil, ErrSTSMissingSigV4
	}

	return parsedURL, qs, nil
}

// ValidateEksToken validates an EKS token and returns the ARN
func (s *Sts) ValidateEksToken(ctx context.Context, eksToken string) (_ string, err error) {
	defer err2.Handle(&err)

	presignedURL := try.To1(s.DecodeEksToken(eksToken))
	_, qs := try.To2(s.ValidatePresignedURL(presignedURL))

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
		return "", fmt.Errorf("%w: %s", ErrSTSMissingSignedHeader, signedHeaders)
	}

	extraHeaders := map[string]string{
		"x-k8s-aws-id": s.clusterID,
	}

	return s.callSTS(ctx, presignedURL, extraHeaders)
}

// callSTS makes the actual STS call
func (s *Sts) callSTS(
	ctx context.Context,
	presignedURL string,
	extraHeaders map[string]string,
) (_ string, err error) {
	defer err2.Handle(&err)

	req := try.To1(http.NewRequestWithContext(ctx, "GET", presignedURL, nil))
	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	// Avoid logging sensitive presigned URLs
	s.logger.Debug("Calling STS")

	resp := try.To1(s.client.Do(req))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %d", ErrSTSBadStatus, resp.StatusCode)
	}

	body := try.To1(io.ReadAll(resp.Body))

	var response GetCallerIdentityResponse
	try.To(xml.Unmarshal(body, &response))

	if response.Result.Arn == "" {
		// Do not include response body to avoid leaking sensitive data
		return "", ErrSTSNoARN
	}

	s.logger.Info("STS call successful", "arn", response.Result.Arn)
	return response.Result.Arn, nil
}
