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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

type CertificateSigner interface {
	Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error)
}

// KMSSigner provides SSH certificate signing using KMS
type KMSSigner struct {
	sshSigner   ssh.Signer
	caPublicKey ssh.PublicKey
}

func NewKMSSigner(ctx context.Context, keyID string) (*KMSSigner, error) {
	cryptoSigner, err := newKMSSignerImpl(ctx, keyID)
	if err != nil {
		return nil, err
	}

	// Convert crypto.Signer to ssh.Signer
	sshSigner, err := ssh.NewSignerFromSigner(cryptoSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}

	return &KMSSigner{
		sshSigner:   sshSigner,
		caPublicKey: sshSigner.PublicKey(),
	}, nil
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
		SignatureKey: s.caPublicKey,
	}

	if err := cert.SignCert(rand.Reader, s.sshSigner); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return cert, nil
}

func (s *KMSSigner) PublicKey() ssh.PublicKey {
	return s.caPublicKey
}

// kmsSignerImpl implements crypto.Signer used to sign data with a KMS key
// this is the backbone of KMSSigner
type kmsSignerImpl struct {
	kmsClient *kms.Client
	keyID     string
	publicKey crypto.PublicKey
}

func newKMSSignerImpl(ctx context.Context, keyID string) (*kmsSignerImpl, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	kmsClient := kms.NewFromConfig(cfg)

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

	return &kmsSignerImpl{
		kmsClient: kmsClient,
		keyID:     keyID,
		publicKey: rsaPubKey,
	}, nil
}

func (s *kmsSignerImpl) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *kmsSignerImpl) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signResp, err := s.kmsClient.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with KMS: %w", err)
	}

	return signResp.Signature, nil
}
