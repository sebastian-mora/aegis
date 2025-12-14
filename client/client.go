package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// PublicKeySigner defines the methods for interacting with a key signing service.
type PublicKeySigner interface {
	// SubmitPublicKey submits a public key to the server.
	// It returns the signed public key or an error if the request fails.
	SubmitPublicKey(PublicKeySignRequest) ([]byte, error)
}

type PublicKeySignRequest struct {
	// PublicKey is the public key to be signed.
	PublicKey string

	// TTL is the time-to-live for the signed key in minutes. (optional)
	TTL time.Duration
}

type AegisClient struct {
	// Endpoint is the URL of the signing service.
	Endpoint string
	// AccessToken is the token used for authentication.
	AccessToken string
	// Client is the HTTP client used for making requests.
	Client *http.Client
}

// NewAegisClient creates a new AegisClient with the specified endpoint and authentication token.
func NewAegisClient(endpoint, accessToken string) *AegisClient {
	return &AegisClient{
		Endpoint:    endpoint,
		AccessToken: accessToken,
		Client:      &http.Client{},
	}
}

// SubmitPublicKey submits a public key to the signing service and returns the signed public key.
// It takes an access token, the public key, and an optional TTL (time-to-live) for the signed key in minutes.
func (c *AegisClient) SubmitPublicKey(data PublicKeySignRequest) ([]byte, error) {

	endpoint, err := url.JoinPath(c.Endpoint, "sign_user_key")
	if err != nil {
		return nil, fmt.Errorf("failed to join signing endpoint path: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(data.PublicKey))

	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Content-Type", "text/plain")

	if data.TTL > 0 {
		ttlMinutes := int(data.TTL.Minutes())
		query := req.URL.Query()
		query.Set("ttl", fmt.Sprintf("%d", ttlMinutes))
		req.URL.RawQuery = query.Encode()
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %s: %s", resp.Status, string(body))
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response from server")
	}

	return body, nil
}
