package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

type SSHCertificateSigner interface {
	ssh.Signer
	CreateSignedCertificate(certType uint32, userPubKey ssh.PublicKey, principals []string, validDuration time.Duration) (*ssh.Certificate, error)
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
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with KMS: %w", err)
	}

	return &ssh.Signature{
		Format: "ssh-rsa",
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
// valid for the specified duration
func (s *SSHCertSigner) CreateSignedCertificate(certType uint32, userPubKey ssh.PublicKey, principals []string, validDuration time.Duration) (*ssh.Certificate, error) {
	cert := &ssh.Certificate{
		Key:             userPubKey,
		KeyId:           "user-cert-" + time.Now().Format("20060102-150405"),
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
