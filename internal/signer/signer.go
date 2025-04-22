package signer

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/jmespath/go-jmespath"
	"golang.org/x/crypto/ssh"
)

type Signer interface {
	Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error)
}

type PrincipalMapper interface {
	Map(claims map[string]interface{}) ([]string, error)
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

// Create PrincipalMapper using JMESPath

type JMESPathPrincipalMapper struct {
	Expressions []string
}

func (m *JMESPathPrincipalMapper) Map(claims map[string]interface{}) ([]string, error) {

	// Check if claims is nil
	if claims == nil {
		return nil, fmt.Errorf("claims cannot be nil")
	}

	seen := make(map[string]struct{})
	var principals []string

	for _, expr := range m.Expressions {
		result, err := jmespath.Search(expr, claims)
		if err != nil {
			return nil, err
		}

		switch v := result.(type) {
		case string:
			if _, exists := seen[v]; !exists {
				seen[v] = struct{}{}
				principals = append(principals, v)
			}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					if _, exists := seen[s]; !exists {
						seen[s] = struct{}{}
						principals = append(principals, s)
					}
				}
			}
		}
	}

	return principals, nil
}
