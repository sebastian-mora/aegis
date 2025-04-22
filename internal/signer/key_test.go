package signer_test

import (
	"strings"
	"testing"

	"github.com/sebastian-mora/aegis/internal/signer"
)

func TestNewEd25519KeyPair(t *testing.T) {
	// Generate a new Ed25519 key pair
	publicKey, privateKey, err := signer.NewSSHKeyPair(signer.Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check if the public key is in the expected format
	if !strings.HasPrefix(publicKey, "ssh-ed25519") {
		t.Errorf("Public key format is incorrect: %s", publicKey)
	}

	// Check if the private key is in PEM format
	if !strings.HasPrefix(privateKey, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("Private key format is incorrect: %s", privateKey)
	}
}
