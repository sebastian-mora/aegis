package signer_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

func TestSign(t *testing.T) {

	// Generate a user Ed25519 key pair to sign
	publicKeyStr, _, err := signer.NewSSHKeyPair(signer.Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Generate a real RSA key for the CA signer
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Encode public key to DER format (as KMS would return it)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&rsaPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create a mock KMS client with real RSA signing
	kmsClient := NewMockKMSClient().
		WithGetPublicKey(func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: pubKeyDER,
			}, nil
		}).
		WithSign(func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			// Perform real RSA signing with SHA256
			digest := sha256.Sum256(params.Message)
			sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}
			return &kms.SignOutput{
				Signature: sig,
			}, nil
		})

	// Create a new KMSSigner with the mocked KMS client
	sshSigner, err := signer.NewSSHCertSigner(context.TODO(), kmsClient, "id-123")
	if err != nil {
		t.Fatalf("Failed to create KMSSigner: %v", err)
	}

	// Sign the public key with the CA signer
	cert, err := sshSigner.Sign(ssh.UserCert, pubKey, []string{"user1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create a mock KMS client with real RSA signing
	kmsClient := NewMockKMSClient().
		WithGetPublicKey(func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: pubKeyDER,
			}, nil
		}).
		WithSign(func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			// Perform real RSA signing with SHA256
			digest := sha256.Sum256(params.Message)
			sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}
			return &kms.SignOutput{
				Signature: sig,
			}, nil
		})

	// Create a new KMSSigner with the mocked KMS client
	sshSigner, err := signer.NewSSHCertSigner(context.TODO(), kmsClient, "id-123")
	if err != nil {
		t.Fatalf("Failed to create KMSSigner: %v", err)
	}

	// Build the public key with the CA signer
	cert, err := sshSigner.CreateSignedCertificate(ssh.UserCert, pubKey, []string{"user1"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to build certificate: %v", err)
	}


	// Check certificate fields
	if cert.CertType != ssh.UserCert {
		t.Errorf("Expected certificate type %d, got %d", ssh.UserCert, cert.CertType)
	}

	if cert.Key.Type() != pubKey.Type() {
		t.Errorf("Expected public key type %s, got %s", pubKey.Type(), cert.Key.Type())
	}

	if cert.SignatureKey.Type() != sshSigner.PublicKey().Type() {
		t.Errorf("Expected signature key type %s, got %s", sshSigner.PublicKey().Type(), cert.SignatureKey.Type())
	}

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
