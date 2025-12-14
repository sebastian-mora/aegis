package audit

import "time"

type KeySignEvent struct {
	ID               string    // Timestamp + SUB
	SignedAt         time.Time // Timestamp of the signing event
	PublicKey        string    // Original public key
	CertificateKeyId string    // Key ID of the signed certificate
	Principals       []string  // List of SSH principals
	SourceIp         string    // IP address where the request came from
	UserAgent        string    // Optional: User agent of the requestor
	Sub              string    // Subject (user ID)
	Aud              string    // Audience (who this was issued for)
	ExpiresAt        time.Time // Optional: for TTL
}
