package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/handler"
	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func generateSSHKey() (*rsa.PrivateKey, *ssh.PublicKey, error) {
	// Generate the RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Generate the corresponding SSH public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &publicKey, nil
}

func setupHandler(jsmeExpression string) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	caPrivateKey, _, _ := generateSSHKey()
	caCertSigner, _ := ssh.NewSignerFromKey(caPrivateKey)

	sshSigner := signer.NewSSHCASigner(caCertSigner)

	principalMapper, _ := signer.NewJMESPathPrincipalMapper(jsmeExpression)

	signerHandler := handler.NewSignerHandler(sshSigner, principalMapper, &MockAuditRepo{})
	apigwHandler := NewAPIGatewayHandler(signerHandler)

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

			handler := setupHandler(tt.jmesExpr)
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

	handler := setupHandler("[]")
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

	assert.Contains(t, resp.Body, "no principals matched from token")

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

	handler := setupHandler("name")
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
