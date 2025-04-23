package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

// Structure includes Standared Claims
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

type IdTokenClaims struct {
	Sub                 string `json:"sub"`
	Name                string `json:"name"`
	GivenName           string `json:"given_name"`
	FamilyName          string `json:"family_name"`
	MiddleName          string `json:"middle_name"`
	Nickname            string `json:"nickname"`
	Profile             string `json:"profile"`
	Picture             string `json:"picture"`
	Website             string `json:"website"`
	Email               string `json:"email"`
	EmailVerified       bool   `json:"email_verified"`
	Gender              string `json:"gender"`
	Birthdate           string `json:"birthdate"`
	Zoneinfo            string `json:"zoneinfo"`
	Locale              string `json:"locale"`
	PhoneNumber         string `json:"phone_number"`
	PhoneNumberVerified bool   `json:"phone_number_verified"`
	Address             string `json:"address"`
	UpdatedAt           int64  `json:"updated_at"`
	Exp                 int64  `json:"exp"`
}

func RequestDeviceCode(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	response, err := config.DeviceAuth(ctx)

	if err != nil {
		return nil, err
	}

	fmt.Printf("📲 To authenticate, visit: %s\n", response.VerificationURIComplete)

	// Poll for the token
	token, err := config.DeviceAccessToken(ctx, response)
	if err != nil {
		return nil, err
	}

	// Return the token
	return token, nil
}

// Function returns parsed strucutre of the ID token
func ParseAccessToken(idToken string) (*IdTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims IdTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ID token payload: %w", err)
	}

	return &claims, nil
}
