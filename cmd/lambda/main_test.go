package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/aws/aws-lambda-go/events"
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

func TestLambdaHandlerWithStringClaims(t *testing.T) {
	// Shared setup
	caPrivateKey, _, err := generateSSHKey()
	assert.NoError(t, err)
	caCertSigner, err := ssh.NewSignerFromKey(caPrivateKey)
	assert.NoError(t, err)
	sshSigner := signer.NewSSHCASigner(caCertSigner)

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
			principalMapper, err := signer.NewJMESPathPrincipalMapper(tt.jmesExpr)
			assert.NoError(t, err)

			handler := NewHandler(LambdaDeps{
				Signer:          sshSigner,
				PrincipalMapper: principalMapper,
			})

			event := events.APIGatewayV2HTTPRequest{
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{
							Claims: tt.claims,
						},
					},
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
