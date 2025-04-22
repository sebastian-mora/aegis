package signer_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func generateSSHKey() (*rsa.PrivateKey, *ssh.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &publicKey, nil
}

func generateMockToken(payload string) string {
	// Generate a mock JWT token
	header := base64.StdEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	signature := base64.StdEncoding.EncodeToString([]byte("mock-signature"))
	token := header + "." + base64.StdEncoding.EncodeToString([]byte(payload)) + "." + signature

	return token

}

func TestSign(t *testing.T) {
	// Generate a new SSH key pair for CA
	caPrivateKey, _, err := generateSSHKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key pair: %v", err)
	}

	// Generate a new Ed25519 key pair
	publicKeyStr, _, err := signer.NewSSHKeyPair(signer.Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Create ssh.Signer from the private key
	caCertSigner, err := ssh.NewSignerFromKey(caPrivateKey)
	if err != nil {
		t.Fatalf("Failed to create SSH signer from CA private key: %v", err)
	}

	// Create a new SSHCASigner with the generated private key
	sshSigner := signer.NewSSHCASigner(caCertSigner)

	// Sign the public key with the CA signer
	cert, err := sshSigner.Sign(ssh.UserCert, pubKey, []string{"user1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to sign certificate: %v", err)
	}

	// Check certificate fields
	if cert.CertType != ssh.UserCert {
		t.Errorf("Expected certificate type %d, got %d", ssh.UserCert, cert.CertType)
	}

	// if !ssh.KeysEqual(cert.Key, pubKey) {
	// 	t.Errorf("Expected public key %v, got %v", pubKey, cert.Key)
	// }

	// if !ssh.KeysEqual(cert.SignatureKey, caCertSigner.PublicKey()) {
	// 	t.Errorf("Expected signature key %v, got %v", caCertSigner.PublicKey(), cert.SignatureKey)
	// }

	// Allow a small delta for timing differences
	now := uint64(time.Now().Unix())
	expectedBefore := now + uint64(24*time.Hour.Seconds())

	if diff := now - cert.ValidAfter; diff > 5 {
		t.Errorf("Expected valid after to be near %d, got %d", now, cert.ValidAfter)
	}
	if diff := cert.ValidBefore - expectedBefore; diff > 5 {
		t.Errorf("Expected valid before to be near %d, got %d", expectedBefore, cert.ValidBefore)
	}

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "user1" {
		t.Errorf("Expected principal %q, got %v", "user1", cert.ValidPrincipals)
	}
}

func TestJMESPrincipalMapper(t *testing.T) {
	// Create a new JMESPathPrincipalMapper
	mapper := &signer.JMESPathPrincipalMapper{
		Expressions: []string{"sub", "email", "groups[*]"},
	}

	// Generate a mock JWT token with payload
	payload := `{"sub":"user1","email":"test@test.com", "groups":["group1","group2", "user1"]}`
	token := generateMockToken(payload)

	expectedPrincipals := []string{"user1", "test@test.com", "group1", "group2"}
	principals, err := mapper.Map(token)

	assert.NoError(t, err)
	assert.Equal(t, expectedPrincipals, principals)
}
