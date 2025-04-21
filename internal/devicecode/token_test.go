package devicecode_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sebastian-mora/aegis/internal/devicecode"
	"github.com/stretchr/testify/assert"
)

func TestParseIdToken(t *testing.T) {

	// Create a test ID Token
	payload := devicecode.IDTokenClaims{
		ISS:           "https://example.com",
		Sub:           "1234567890",
		Aud:           "my-client-id",
		Exp:           1625247600,
		Iat:           1625244000,
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
		Scope:         "openid profile email",
		Groups:        []string{"group1", "group2"},
		Azp:           "my-client-id",
		UID:           "user-id",
	}

	// Create mock header and signature
	header := `{"alg":"RS256","typ":"JWT"}`
	signature := "signature"

	// Marshal the payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Construct the ID token string (header.payload.signature)
	idTokenString := header + "." + string(encodedPayload) + "." + signature

	// Call the function to parse the ID token
	claims, err := devicecode.ParseIDToken(idTokenString)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Validate the parsed claims using assertions
	assert.Equal(t, payload.ISS, claims.ISS)
	assert.Equal(t, payload.Sub, claims.Sub)
	assert.Equal(t, payload.Aud, claims.Aud)
	assert.Equal(t, payload.Exp, claims.Exp)
	assert.Equal(t, payload.Iat, claims.Iat)
	assert.Equal(t, payload.Email, claims.Email)
	assert.Equal(t, payload.Name, claims.Name)
	assert.Equal(t, payload.EmailVerified, claims.EmailVerified)
	assert.Equal(t, payload.Scope, claims.Scope)
	assert.Equal(t, len(payload.Groups), len(claims.Groups))

	// Compare Groups slice
	for i, group := range claims.Groups {
		assert.Equal(t, payload.Groups[i], group)
	}

	assert.Equal(t, payload.Azp, claims.Azp)
	assert.Equal(t, payload.UID, claims.UID)
}
