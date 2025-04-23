package signer

import (
	"crypto/rand"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

type Signer interface {
	Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error)
}

type SSHCASigner struct {
	Signer ssh.Signer
}

func NewSSHCASigner(signer ssh.Signer) *SSHCASigner {
	return &SSHCASigner{Signer: signer}
}

func (s *SSHCASigner) Sign(certType uint32, publicKey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error) {
	now := time.Now()

	var cert *ssh.Certificate
	switch certType {
	case ssh.UserCert:
		cert = &ssh.Certificate{
			Key:             publicKey,
			KeyId:           "user-cert-" + now.Format("20060102-150405"),
			CertType:        ssh.UserCert,
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
		}

	default:
		return nil, fmt.Errorf("unsupported certificate type: %d", certType)
	}

	if err := cert.SignCert(rand.Reader, s.Signer); err != nil {
		return nil, err
	}

	return cert, nil
}
