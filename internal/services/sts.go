package services

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/joomcode/errorx"

	apperrors "github.com/rgeraskin/aws-ldap-authenticator/internal/errors"
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

// DecodeEKSToken decodes an EKS token to get the presigned URL
func (s *STSService) DecodeEKSToken(eksToken string) (string, error) {
	const prefix = "k8s-aws-v1."
	if !strings.HasPrefix(eksToken, prefix) {
		return "", apperrors.ErrTokenInvalidPrefix
	}

	b64 := eksToken[len(prefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", errorx.Decorate(apperrors.ErrTokenMalformedPayload, err.Error())
	}

	return string(decoded), nil
}

// ValidatePresignedURL validates a presigned STS URL
func (s *STSService) ValidatePresignedURL(urlStr string) (*url.URL, url.Values, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, errorx.Decorate(apperrors.ErrTokenInvalidURL, err.Error())
	}

	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	if !s.stsHosts[origin] {
		return nil, nil, errorx.Decorate(apperrors.ErrSTSUntrustedHost, origin)
	}

	qs := parsedURL.Query()
	action := qs.Get("Action")
	if action != "GetCallerIdentity" {
		return nil, nil, errorx.Decorate(apperrors.ErrSTSInvalidAction, action)
	}

	// Must be SigV4 signed
	if qs.Get("X-Amz-Algorithm") == "" || qs.Get("X-Amz-Signature") == "" {
		return nil, nil, apperrors.ErrSTSMissingSigV4
	}

	return parsedURL, qs, nil
}

// ValidateEKSToken validates an EKS token and returns the ARN
func (s *STSService) ValidateEKSToken(ctx context.Context, eksToken string) (string, error) {
	presignedURL, err := s.DecodeEKSToken(eksToken)
	if err != nil {
		return "", err
	}

	_, qs, err := s.ValidatePresignedURL(presignedURL)
	if err != nil {
		return "", err
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
		return "", errorx.Decorate(apperrors.ErrSTSMissingSignedHeader, signedHeaders)
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
		return "", errorx.Decorate(apperrors.ErrSTSCreateRequest, err.Error())
	}

	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	// Avoid logging sensitive presigned URLs
	s.logger.Debug("Calling STS")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", errorx.Decorate(apperrors.ErrSTSRequestFailed, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errorx.Decorate(apperrors.ErrSTSBadStatus, strconv.Itoa(resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errorx.Decorate(apperrors.ErrSTSReadResponse, err.Error())
	}

	var response GetCallerIdentityResponse
	if err := xml.Unmarshal(body, &response); err != nil {
		return "", errorx.Decorate(apperrors.ErrSTSParseResponse, err.Error())
	}

	if response.Result.Arn == "" {
		// Do not include response body to avoid leaking sensitive data
		return "", apperrors.ErrSTSNoARN
	}

	s.logger.Info("STS call successful", "arn", response.Result.Arn)
	return response.Result.Arn, nil
}
