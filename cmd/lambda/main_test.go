package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/principals"
	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
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

func setupHandler(jsmeExpression string, t *testing.T) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Create a mock KMS API
	mockKMS := NewMockKMSAPI(t)

	// Create a real KMSSigner backed by the mock KMS API
	sshSigner, err := signer.NewKMSSigner(context.Background(), mockKMS, "test-key-id")
	if err != nil {
		t.Fatalf("Failed to create KMSSigner: %v", err)
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

func setupHandler(jsmeExpression string, t *testing.T) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Create a mock KMS API
	mockKMS := NewMockKMSAPI(t)

	// Create a real KMSSigner backed by the mock KMS API
	sshSigner, err := signer.NewSSHCertSigner(context.Background(), mockKMS, "test-key-id")
	if err != nil {
		t.Fatalf("Failed to create KMSSigner: %v", err)
	}

	principalMapper, _ := principals.NewJMESPathPrincipalMapper(jsmeExpression)

	apigwHandler, _ := initialize(context.Background(),
		WithSSHCertificateSigner(sshSigner),
		WithPrincipalMapper(principalMapper),
		WithAuditStore(&MockAuditRepo{}),
	)

	return apigwHandler.Handle
}

type MockAuditRepo struct{}

func (a *MockAuditRepo) Write(event audit.KeySignEvent) error {
	return nil
}

func signJWTWithSecret(claims map[string]string, secret string) (string, error) {
	mapClaims := jwt.MapClaims{
		"aud": "test-aud",
		"sub": "test-sub",
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
			assert.True(t, ok)
			assert.ElementsMatch(t, tt.expectedPrin, sshCert.ValidPrincipals)
		})
	}
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
