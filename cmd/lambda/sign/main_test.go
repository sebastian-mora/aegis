package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/principals"
	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type MockKMSAPI struct {
	privateKey *rsa.PrivateKey
}

func NewMockKMSAPI(t *testing.T) *MockKMSAPI {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return &MockKMSAPI{privateKey: privateKey}
}

func (m *MockKMSAPI) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	digest := sha256.Sum256(params.Message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{
		Signature: sig,
	}, nil
}

func (m *MockKMSAPI) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&m.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		PublicKey: pubKeyDER,
	}, nil
}

func setupHandlerWithAudit(jsmeExpression string, t *testing.T) (func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error), *MockAuditRepo) {
	// Create a mock KMS API
	mockKMS := NewMockKMSAPI(t)

	// Create a real KMSSigner backed by the mock KMS API
	sshSigner, err := signer.NewSSHCertSigner(context.Background(), mockKMS, "test-key-id")
	if err != nil {
		t.Fatalf("Failed to create KMSSigner: %v", err)
	}

	principalMapper, _ := principals.NewJMESPathPrincipalMapper(jsmeExpression)

	auditRepo := &MockAuditRepo{}
	apigwHandler, _ := initialize(context.Background(),
		WithSSHCertificateSigner(sshSigner),
		WithPrincipalMapper(principalMapper),
		WithAuditStore(auditRepo),
	)

	return apigwHandler.Handle, auditRepo
}

func setupHandler(jsmeExpression string, t *testing.T) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	handler, _ := setupHandlerWithAudit(jsmeExpression, t)
	return handler
}

type MockAuditRepo struct {
	Events []audit.KeySignEvent
}

func (a *MockAuditRepo) Write(event audit.KeySignEvent) error {
	a.Events = append(a.Events, event)
	return nil
}

func signJWTWithSecret(claims map[string]string, secret string) (string, error) {
	// Defaults for the claims the handler requires on every request; individual
	// tests override them by passing the same key in claims.
	mapClaims := jwt.MapClaims{
		"aud": "test-aud",
		"sub": "test-sub",
		"iss": "https://idp.example.com",
	}
	for k, v := range claims {
		var parsed interface{}
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			mapClaims[k] = parsed
		} else {
			mapClaims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	return token.SignedString([]byte(secret))
}

func TestLambdaHandlerWithStringClaims(t *testing.T) {

	pubkey, _, err := signer.NewSSHKeyPair(signer.ECDSA)
	assert.NoError(t, err)

	tests := []struct {
		name         string
		jmesExpr     string
		claims       map[string]string
		expectedPrin []string
		expectError  bool
	}{
		{
			name:         "Single email claim",
			jmesExpr:     "email",
			claims:       map[string]string{"email": "alice@example.com"},
			expectedPrin: []string{"alice@example.com"},
		},
		{
			name:         "Test unpacking list",
			jmesExpr:     "unix_groups[*]",
			claims:       map[string]string{"unix_groups": "[\"group_1\", \"group_2\"]"},
			expectedPrin: []string{"group_1", "group_2"},
		},
		{
			name:         "Test muilt attrs",
			jmesExpr:     "[sub, email]",
			claims:       map[string]string{"email": "alice@example.com", "sub": "alice"},
			expectedPrin: []string{"alice@example.com", "alice"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			handler := setupHandler(tt.jmesExpr, t)
			tokenString, err := signJWTWithSecret(tt.claims, "test123")
			assert.NoError(t, err)

			event := events.APIGatewayV2HTTPRequest{
				Headers: map[string]string{
					"authorization": "Bearer " + tokenString,
				},
				RawPath: "/sign_user_key",
				Body:    pubkey,
			}

			resp, err := handler(context.Background(), event)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, 200, resp.StatusCode)

			parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Body))
			assert.NoError(t, err)

			sshCert, ok := parsedKey.(*ssh.Certificate)
			require.True(t, ok, "expected response body to be a certificate, got %q", resp.Body)
			assert.ElementsMatch(t, tt.expectedPrin, sshCert.ValidPrincipals)
		})
	}
}

func TestAuditEventIdentityAndFingerprints(t *testing.T) {
	pubkey, _, err := signer.NewSSHKeyPair(signer.ECDSA)
	assert.NoError(t, err)

	handler, auditRepo := setupHandlerWithAudit("email", t)
	tokenString, err := signJWTWithSecret(map[string]string{
		"email": "alice@example.com",
		"iss":   "https://idp.example.com",
	}, "test123")
	assert.NoError(t, err)

	event := events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{"authorization": "Bearer " + tokenString},
		RawPath: "/sign_user_key",
		Body:    pubkey,
	}

	resp, err := handler(context.Background(), event)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	assert.Len(t, auditRepo.Events, 1)
	auditEvent := auditRepo.Events[0]

	assert.Equal(t, "https://idp.example.com", auditEvent.Iss)
	assert.Equal(t, "test-sub", auditEvent.Sub)

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Body))
	assert.NoError(t, err)
	cert, ok := parsedKey.(*ssh.Certificate)
	require.True(t, ok, "expected response body to be a certificate, got %q", resp.Body)

	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	assert.NoError(t, err)
	assert.Equal(t, ssh.FingerprintSHA256(userKey), auditEvent.PublicKeyFingerprint)
	assert.Equal(t, ssh.FingerprintSHA256(cert.Key), auditEvent.PublicKeyFingerprint)

	assert.Equal(t, ssh.FingerprintSHA256(cert.SignatureKey), auditEvent.CAPublicKeyFingerprint)

	// The key ID identifies this issuance: it is recorded verbatim in the audit
	// log and carries the subject so sshd's login records stay attributable.
	assert.Equal(t, cert.KeyId, auditEvent.CertificateKeyId)
	assert.True(t, strings.HasPrefix(cert.KeyId, "test-sub-"))
}

func TestLambdaHandlerWithNoMatchingClaims(t *testing.T) {

	pubkey, _, err := signer.NewSSHKeyPair(signer.ECDSA)
	assert.NoError(t, err)

	handler := setupHandler("[]", t)
	tokenString, _ := signJWTWithSecret(map[string]string{}, "test123")

	event := events.APIGatewayV2HTTPRequest{
		Headers: map[string]string{
			"authorization": "Bearer " + tokenString,
		},
		RawPath: "/sign_user_key",
		Body:    pubkey,
	}

	resp, err := handler(context.Background(), event)

	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode)

}

func TestLambdaHandlerWithTTls(t *testing.T) {
	tests := []struct {
		name               string
		ttl                string
		expectedTTL        time.Duration
		expectedStatusCode int
	}{
		{
			name:               "Default TTL",
			ttl:                "",
			expectedTTL:        24 * time.Hour,
			expectedStatusCode: 200,
		},
		{
			name:               "Custom TTL",
			ttl:                "720",
			expectedTTL:        12 * time.Hour,
			expectedStatusCode: 200,
		},
		{
			name:               "Invalid TTL",
			ttl:                "invalid",
			expectedTTL:        0,
			expectedStatusCode: 400,
		},
		{
			name:               "Negative TTL",
			ttl:                "-60",
			expectedTTL:        0,
			expectedStatusCode: 400,
		},
		{
			name:               "Zero TTL",
			ttl:                "0",
			expectedTTL:        0,
			expectedStatusCode: 400,
		},
		{
			name:               "TTL > 30 days",
			ttl:                "44640",
			expectedTTL:        0,
			expectedStatusCode: 400,
		},
	}

	pubkey, _, err := signer.NewSSHKeyPair(signer.ECDSA)
	assert.NoError(t, err)

	handler := setupHandler("name", t)
	tokenString, err := signJWTWithSecret(map[string]string{"name": "ruse"}, "test123")

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			event := events.APIGatewayV2HTTPRequest{
				Headers: map[string]string{
					"authorization": "Bearer " + tokenString,
				},
				RawPath: "/sign_user_key",
				Body:    pubkey,
				QueryStringParameters: map[string]string{
					"ttl": tt.ttl,
				},
			}

			resp, err := handler(context.Background(), event)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatusCode, resp.StatusCode)

			if tt.expectedStatusCode == 200 {
				parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Body))
				assert.NoError(t, err)

				sshCert, ok := parsedKey.(*ssh.Certificate)
				assert.True(t, ok)
				assert.LessOrEqual(t, sshCert.ValidBefore, uint64(time.Now().Add(tt.expectedTTL).Unix()))
			}
		})
	}
}
