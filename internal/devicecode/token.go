package devicecode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type TokenClaims struct {
	ISS           string   `json:"iss"`
	Sub           string   `json:"sub"`
	Aud           string   `json:"aud"`
	Exp           int64    `json:"exp"`
	Iat           int64    `json:"iat"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	EmailVerified bool     `json:"email_verified"`
	Scope         string   `json:"scope"`
	Groups        []string `json:"groups"`
	Azp           string   `json:"azp"`
	UID           string   `json:"uid"`
}

// Function returns parsed strucutre of the ID token
func ParseAccessToken(idToken string) (*TokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ID token payload: %w", err)
	}

	return &claims, nil
}
