package signer

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"golang.org/x/crypto/ssh"
)

type SignerSource interface {
	Load() (ssh.Signer, error)
}

// --- File-based source ---
type FileSource struct {
	Path string
}

func (f *FileSource) Load() (ssh.Signer, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// --- AWS Secrets Manager source ---
type AWSSMSource struct {
	secretName string
	session    *session.Session
}

func NewAWSSMSource(secretName string, session *session.Session) SignerSource {
	return &AWSSMSource{
		secretName: secretName,
		session:    session,
	}
}

func (a *AWSSMSource) Load() (ssh.Signer, error) {
	svc := secretsmanager.New(a.session)
	out, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: &a.secretName,
	})
	if err != nil {
		return nil, err
	}

	if out.SecretString == nil {
		return nil, fmt.Errorf("secret %s has no SecretString", a.secretName)
	}

	return ssh.ParsePrivateKey([]byte(*out.SecretString))
}
