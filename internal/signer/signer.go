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

type CertificateSigner interface {
	Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error)
}

// KMSSigner provides SSH certificate signing using KMS
type KMSSigner struct {
	kmsClient AwsKMSApi
	keyID     string
	publicKey crypto.PublicKey
	sshSigner ssh.Signer
}

func NewKMSSigner(ctx context.Context, kmsClient AwsKMSApi, keyID string) (*KMSSigner, error) {

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

	s := &KMSSigner{
		kmsClient: kmsClient,
		keyID:     keyID,
		publicKey: rsaPubKey,
	}

	// Convert crypto.Signer to ssh.Signer
	sshSigner, err := ssh.NewSignerFromSigner(&kmsSignerAdapter{s})
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}

	s.sshSigner = sshSigner

	return s, nil
}

func (s *KMSSigner) Sign(certType uint32, publicKey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error) {
	now := time.Now()

	cert := &ssh.Certificate{
		Key:             publicKey,
		KeyId:           "user-cert-" + now.Format("20060102-150405"),
		CertType:        certType,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(expiration).Unix()),
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

	if err := cert.SignCert(rand.Reader, s.sshSigner); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return cert, nil
}

func (s *KMSSigner) PublicKey() ssh.PublicKey {
	sshPubKey, err := ssh.NewPublicKey(s.publicKey)
	if err != nil {
		panic(fmt.Sprintf("failed to convert public key to SSH format: %v", err))
	}
	return sshPubKey
}

// kmsSignerAdapter adapts KMSSigner to implement crypto.Signer for use with ssh.NewSignerFromSigner
type kmsSignerAdapter struct {
	*KMSSigner
}

func (a *kmsSignerAdapter) Public() crypto.PublicKey {
	return a.publicKey
}

func (a *kmsSignerAdapter) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signResp, err := a.kmsClient.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &a.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with KMS: %w", err)
	}

	return signResp.Signature, nil
}
