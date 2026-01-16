package handler

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/logger"
	"github.com/sebastian-mora/aegis/internal/principals"
	signerPkg "github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrInvalidRequest = errors.New("invalid request")
var ErrInternalServer = errors.New("internal server error")

// SigningRequest represents a request to sign a certificate
type SigningRequest struct {
	Token     string // JWT token
	PublicKey string // SSH public key
	TTL       string // Time-to-live in minutes
	SourceIP  string // Source IP address
	UserAgent string // User agent
}

// SigningResponse represents the response from a signing request
type SigningResponse struct {
	Certificate string // Signed SSH certificate
	ExpiresAt   time.Time
}

// Signer defines the interface for signing operations
type Signer interface {
	SignRequest(ctx context.Context, req *SigningRequest) (*SigningResponse, error)
}

// SignerHandler implements the Signer interface
type SignerHandler struct {
	signer          signerPkg.SSHCertificateSigner
	principalMapper principals.PrincipalMapper
	auditRepo       audit.AuditWriter
}

// NewSignerHandler creates a new SignerHandler with the provided dependencies
func NewSignerHandler(s signerPkg.SSHCertificateSigner, pm principals.PrincipalMapper, ar audit.AuditWriter) *SignerHandler {
	return &SignerHandler{
		signer:          s,
		principalMapper: pm,
		auditRepo:       ar,
	}
}

// SignRequest processes a signing request and returns a signed certificate
func (h *SignerHandler) SignRequest(ctx context.Context, req *SigningRequest) (*SigningResponse, error) {
	var certificateExpiration = time.Duration(24 * time.Hour)

	// Parse JWT claims
	parsedTokenClaims, err := ParseJWTClaims(req.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}

	// Extract required claims
	aud, audOk := parsedTokenClaims["aud"].(string)
	sub, subOk := parsedTokenClaims["sub"].(string)
	if !audOk || !subOk {
		return nil, fmt.Errorf("%w: missing required claims", ErrUnauthorized)
	}

	// Add subject to context for logging
	ctx = context.WithValue(ctx, logger.SubjectKey, sub)

	logger.Info(ctx, "Processing certificate signing request", "claims", parsedTokenClaims)

	// Map JWT claims to SSH principals
	principals, err := h.principalMapper.Map(parsedTokenClaims)
	if err != nil {
		logger.Error(ctx, "failed to map principals from JWT claims", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrInternalServer, err)
	}
	logger.Info(ctx, "Mapped principals from JWT claims", "principals", principals)
	// Parse public key from request
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse public key", ErrInvalidRequest)
	}

	// Parse TTL from query string if provided
	if req.TTL != "" {
		ttl, err := ParseTTL(req.TTL)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse ttl", ErrInvalidRequest)
		}
		logger.Info(ctx, "Parsed TTL from request", "ttl", ttl)
		certificateExpiration = ttl
	}

	// Sign the certificate
	userSSHCert, err := h.signer.CreateSignedCertificate(ssh.UserCert, pubKey, principals, certificateExpiration)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}
	logger.Info(ctx, "Successfully signed certificate", "certificate", userSSHCert.KeyId)

	// Return the SSH certificate
	certString := string(ssh.MarshalAuthorizedKey(userSSHCert))
	expiresAt := time.Unix(int64(userSSHCert.ValidBefore), 0).UTC()

	// Write event to audit trail
	keySignEvent := audit.KeySignEvent{
		SignedAt:         time.Now().UTC(),
		PublicKey:        string(ssh.MarshalAuthorizedKey(pubKey)),
		CertificateKeyId: userSSHCert.KeyId,
		Principals:       principals,
		SourceIp:         req.SourceIP,
		UserAgent:        req.UserAgent,
		Sub:              sub,
		Aud:              aud,
		ExpiresAt:        expiresAt,
	}

	if err := h.auditRepo.Write(keySignEvent); err != nil {
		// note: If audit logging fails, we log the error but do not fail the signing operation
		logger.Error(ctx, "failed to write audit log", "error", err)
	}

	logger.Info(ctx, "certificate signed successfully", "principals", principals)

	return &SigningResponse{
		Certificate: certString,
		ExpiresAt:   expiresAt,
	}, nil
}

// ParseJWTClaims parses a JWT token without verification and returns the claims
// This custom parsing is required due to a bug in the lambda-events SDK
// Tracking issue: https://github.com/aws/aws-lambda-go/issues/570
func ParseJWTClaims(tokenString string) (map[string]interface{}, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return map[string]interface{}(claims), nil
	}

	return nil, fmt.Errorf("invalid token claims type")
}

// ParseTTL parses a TTL string (in minutes) and returns a time.Duration
// Max TTL is 24 hrs
func ParseTTL(ttl string) (time.Duration, error) {
	ttlMinutes, err := strconv.Atoi(ttl)
	if err != nil {
		return 0, fmt.Errorf("failed to parse ttl: %w", err)
	}

	parsedTTL := time.Duration(ttlMinutes) * time.Minute

	if parsedTTL <= 0 {
		return 0, fmt.Errorf("ttl must be greater than 0")
	}

	if parsedTTL > time.Duration(24*time.Hour) {
		return 0, fmt.Errorf("ttl is too long")
	}

	return parsedTTL, nil
}
