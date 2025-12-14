package signer_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/sebastian-mora/aegis/internal/signer"
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
