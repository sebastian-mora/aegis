package signer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type SSHAlgorithm string

const (
	Ed25519 SSHAlgorithm = "ed25519"
	RSA     SSHAlgorithm = "rsa"
	ECDSA   SSHAlgorithm = "ecdsa"
)

func NewSSHKeyPair(algo SSHAlgorithm) (pubKey string, privKey string, err error) {

	// Check if the SSH keygen command is available
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return "", "", fmt.Errorf("ssh-keygen not found: %w", err)
	}

	// Check if the algorithm is supported
	switch algo {
	case Ed25519, RSA, ECDSA:
	default:
		return "", "", fmt.Errorf("unsupported algorithm: %s", algo)
	}

	// Use tmpfs-backed secure location
	tempDir, err := os.MkdirTemp("", "aegis-")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "aegis")

	// Generate the SSH keypair
	cmd := exec.Command("ssh-keygen", "-t", string(algo), "-N", "", "-f", keyPath)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen failed: %w", err)
	}

	// Read private key
	privBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read private key: %w", err)
	}

	// Read public key
	pubBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return "", "", fmt.Errorf("failed to read public key: %w", err)
	}

	return string(pubBytes), string(privBytes), nil
}
