package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func NewEd25519KeyPair() (string, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("key generation failed: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("ssh signer creation failed: %w", err)
	}

	publicKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: priv.Seed(),
	})

	return publicKey, string(privateKeyPEM), nil
}
