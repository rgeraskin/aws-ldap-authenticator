package services

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/log"

	"broker/internal/errors"
)

// STSService handles STS operations
type STSService struct {
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

// NewSTSService creates a new STS service
func NewSTSService(
	stsHosts map[string]bool,
	clusterID string,
	timeout time.Duration,
	logger *log.Logger,
) *STSService {
	return &STSService{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		stsHosts:  stsHosts,
		clusterID: clusterID,
		logger:    logger,
	}
}

// DecodeEKSToken decodes an EKS token to get the presigned URL
func (s *STSService) DecodeEKSToken(eksToken string) (string, error) {
	const prefix = "k8s-aws-v1."
	if !strings.HasPrefix(eksToken, prefix) {
		return "", errors.ErrInvalidTokenPrefix
	}

	b64 := eksToken[len(prefix):]
	// Add padding if missing
	padding := strings.Repeat("=", (4-len(b64)%4)%4)
	b64 += padding

	decoded, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrMalformedTokenPayload, err)
	}

	return string(decoded), nil
}

// ValidatePresignedURL validates a presigned STS URL
func (s *STSService) ValidatePresignedURL(urlStr string) (*url.URL, url.Values, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errors.ErrInvalidURL, err)
	}

	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	if !s.stsHosts[origin] {
		return nil, nil, fmt.Errorf("%w: %s", errors.ErrUntrustedSTSHost, origin)
	}

	qs := parsedURL.Query()
	action := qs.Get("Action")
	if action != "GetCallerIdentity" {
		return nil, nil, fmt.Errorf("%w, got: %s", errors.ErrInvalidSTSAction, action)
	}

	// Must be SigV4 signed
	if qs.Get("X-Amz-Algorithm") == "" || qs.Get("X-Amz-Signature") == "" {
		return nil, nil, errors.ErrMissingSTSSigV4
	}

	return parsedURL, qs, nil
}

// ValidateEKSToken validates an EKS token and returns the ARN
func (s *STSService) ValidateEKSToken(ctx context.Context, eksToken string) (string, error) {
	presignedURL, err := s.DecodeEKSToken(eksToken)
	if err != nil {
		return "", err // Error already wrapped in DecodeEKSToken
	}

	_, qs, err := s.ValidatePresignedURL(presignedURL)
	if err != nil {
		return "", err // Error already wrapped in ValidatePresignedURL
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
		return "", errors.ErrMissingSTSSignedHeader
	}

	extraHeaders := map[string]string{
		"x-k8s-aws-id": s.clusterID,
	}

	return s.callSTS(ctx, presignedURL, extraHeaders)
}

// callSTS makes the actual STS call
func (s *STSService) callSTS(
	ctx context.Context,
	presignedURL string,
	extraHeaders map[string]string,
) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", presignedURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrSTSCreateRequest, err)
	}

	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	s.logger.Debug("Calling STS", "url", presignedURL)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrSTSRequestFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %d", errors.ErrSTSBadStatus, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrSTSReadResponse, err)
	}

	var response GetCallerIdentityResponse
	if err := xml.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrSTSParseResponse, err)
	}

	if response.Result.Arn == "" {
		return "", errors.ErrSTSNoARN
	}

	s.logger.Info("STS call successful", "arn", response.Result.Arn)
	return response.Result.Arn, nil
}
