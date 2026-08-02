package audit

import "time"

type KeySignEvent struct {
	ID                     string    // Timestamp + SUB
	SignedAt               time.Time // Timestamp of the signing event
	PublicKey              string    // Original public key
	PublicKeyFingerprint   string    // SHA256 fingerprint of the user public key, as printed by ssh-keygen and logged by sshd
	CertificateKeyId       string    // Key ID of the signed certificate; unique per issuance and logged by sshd on login
	CAPublicKeyFingerprint string    // SHA256 fingerprint of the CA public key, as shown in the "Signing CA" field
	Principals             []string  // List of SSH principals
	SourceIp               string    // IP address where the request came from
	UserAgent              string    // Optional: User agent of the requestor
	Sub                    string    // Subject (user ID)
	Aud                    string    // Audience (who this was issued for)
	Iss                    string    // Issuer (which IdP authenticated the subject)
	ExpiresAt              time.Time // Optional: for TTL
}
