package signer

import (
	"crypto/rand"
	"time"

	"golang.org/x/crypto/ssh"
)

type Signer interface {
	Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error)
}

type SSHCASigner struct {
	CAPrivateKey ssh.Signer
}

func (s *SSHCASigner) Sign(certType uint32, publicKey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error) {
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             publicKey,
		KeyId:           "user-cert-" + time.Now().Format("20060102-150405"),
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

	if err := cert.SignCert(rand.Reader, s.CAPrivateKey); err != nil {
		return nil, err
	}

	return cert, nil
}
