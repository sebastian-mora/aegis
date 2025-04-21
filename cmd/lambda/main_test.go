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

func TestLambdaHandler(t *testing.T) {
	// Generate a new SSH key pair for CA
	caPrivateKey, _, err := generateSSHKey()
	assert.NoError(t, err)
	caCertSigner, err := ssh.NewSignerFromKey(caPrivateKey)
	assert.NoError(t, err)

	// Initialize the SSH signer
	sshSigner := &signer.SSHCASigner{CAPrivateKey: caCertSigner}

	// Generate a new SSH key pair for the user
	_, pubkey, err := generateSSHKey()
	assert.NoError(t, err)

	// Lambda deps and handler
	deps := LambdaDeps{
		Signer: sshSigner,
	}
	handler := NewHandler(deps)

	// Mock API Gateway event
	event := events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
				JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{
					Claims: map[string]string{
						"email":    "testuser@example.com",
						"username": "testuser",
					},
				},
			},
		},

		RawPath: "/sign_user_key",
		// Dereference pubkey to pass the actual value to MarshalAuthorizedKey
		Body: string(ssh.MarshalAuthorizedKey(*pubkey)), // Dereference the public key here
	}

	// Execute handler
	resp, err := handler(context.Background(), event)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Body, "ssh-rsa") // Just verify output contains expected header

	// Parse the returned certificate
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Body))
	assert.NoError(t, err)
	sshCert, ok := cert.(*ssh.Certificate)
	assert.True(t, ok)

	// Verify the certificate
	assert.Equal(t, sshCert.CertType, uint32(ssh.UserCert))
	assert.Equal(t, sshCert.ValidPrincipals, []string{"testuser@example.com"})
}
