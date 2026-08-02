package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

type SSHCertificateSigner interface {
	ssh.Signer
	CreateSignedCertificate(certType uint32, keyID string, userPubKey ssh.PublicKey, principals []string, validDuration time.Duration) (*ssh.Certificate, error)
}

// NewCertificateKeyID builds a key ID identifying a single certificate issuance.
// sshd logs this value on login, so it carries the subject to make the login
// attributable, plus random bytes so two certificates issued in the same second
// never collide.
func NewCertificateKeyID(subject string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, suffix); err != nil {
		return "", fmt.Errorf("failed to generate key id: %w", err)
	}
	return fmt.Sprintf("%s-%s-%s", subject, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(suffix)), nil
}

// SSHCertSigner provides SSH certificate signing using KMS and implements ssh.Signer
type SSHCertSigner struct {
	kmsClient AwsKMSApi
	keyID     string
	publicKey crypto.PublicKey
}

func NewSSHCertSigner(ctx context.Context, kmsClient AwsKMSApi, keyID string) (*SSHCertSigner, error) {

	// Get the public key from KMS
	pubKeyResp, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS public key: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(pubKeyResp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// TODO: support other key types
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	s := &SSHCertSigner{
		kmsClient: kmsClient,
		keyID:     keyID,
		publicKey: rsaPubKey,
	}

	return s, nil
}

func (s *SSHCertSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	signResp, err := s.kmsClient.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          data,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with KMS: %w", err)
	}

	return &ssh.Signature{
		Format: ssh.KeyAlgoRSASHA512,
		Blob:   signResp.Signature,
	}, nil
}

func (s *SSHCertSigner) PublicKey() ssh.PublicKey {
	sshPubKey, err := ssh.NewPublicKey(s.publicKey)
	if err != nil {
		panic(fmt.Sprintf("failed to convert public key to SSH format: %v", err))
	}
	return sshPubKey
}

// CreateSignedCertificate builds and signs an SSH certificate for the given public key and principals
// valid for the specified duration. keyID identifies this issuance and is logged by sshd on login;
// use NewCertificateKeyID to build one.
func (s *SSHCertSigner) CreateSignedCertificate(certType uint32, keyID string, userPubKey ssh.PublicKey, principals []string, validDuration time.Duration) (*ssh.Certificate, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key id must not be empty")
	}

	cert := &ssh.Certificate{
		Key:             userPubKey,
		KeyId:           keyID,
		CertType:        certType,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(validDuration).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-port-forwarding":  "",
				"permit-agent-forwarding": "",
				"permit-X11-forwarding":   "",
				"permit-user-rc":          "",
			},
		},
		SignatureKey: s.PublicKey(),
	}

	if _, err := io.ReadFull(rand.Reader, cert.Nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	if err := cert.SignCert(rand.Reader, s); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return cert, nil
}
