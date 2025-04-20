package signer

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// PublicKeySigner defines the methods for interacting with a key signing service.
type PublicKeySigner interface {
	// SubmitPublicKey submits a public key to the server.
	// It returns the signed public key or an error if the request fails.
	SubmitPublicKey(idToken, pubKey string) ([]byte, error)
}

type AegisClient struct {
	// Endpoint is the URL of the signing service.
	Endpoint string
	// AuthToken is the token used for authentication.
	IDToken string
	// Client is the HTTP client used for making requests.
	Client *http.Client
}

// NewAegisClient creates a new AegisClient with the specified endpoint and authentication token.
func NewAegisClient(endpoint, idToken string) *AegisClient {
	return &AegisClient{
		Endpoint: endpoint,
		IDToken:  idToken,
		Client:   &http.Client{},
	}
}

// SubmitPublicKey submits a public key to the signing service and returns the signed public key.
func (c *AegisClient) SubmitPublicKey(pubKey string) ([]byte, error) {
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewBufferString(pubKey))

	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Authorization", c.IDToken)
	req.Header.Set("Content-Type", "text/plain")

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
