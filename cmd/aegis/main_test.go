package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

type Signer interface {
	Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error)
}

type mockSigner struct {
}

func (m *mockSigner) Sign(certType uint32, publickkey ssh.PublicKey, principals []string, expiration time.Duration) (*ssh.Certificate, error) {
	return &ssh.Certificate{}, nil
}

func GenerateMockJWT(claims map[string]interface{}, secret string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	// Convert map to jwt.MapClaims
	mapClaims := jwt.MapClaims{}
	for k, v := range claims {
		mapClaims[k] = v
	}
	token.Claims = mapClaims

	// Sign the token with the secret
	return token.SignedString([]byte(secret))
}

// Create test http mock server that signs the public key
func mockSignerServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"signed_key": "mocked-signed-key"}`))
	})

	return httptest.NewServer(mux)
}

func mockDeviceCodeServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/application/o/device/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"device_code": "mock-device-code", "user_code": "mock-user-code", "verification_uri": "https://mock.verification.uri"}`))
	})

	mux.HandleFunc("/application/o/token/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// create token with claims
		claims := map[string]interface{}{
			"sub":  "mock-subject",
			"name": "mock-name",
			"exp":  time.Now().Add(1 * time.Hour).Unix(),
		}
		token, _ := GenerateMockJWT(claims, "test-secret")
		w.Write([]byte(`{"access_token": "` + token + `", "expires_in": 3600}`))
	})

	return httptest.NewServer(mux)
}
func TestRun_Success(t *testing.T) {
	signerServer := mockSignerServer()
	defer signerServer.Close()

	deviceCodeServer := mockDeviceCodeServer()
	defer deviceCodeServer.Close()

	// override the config path to a temp dir
	// this avoids writing to the user's home directory
	// and allows for easier cleanup after tests
	configPathFlag = t.TempDir()

	cfg := ClientConfig{
		AuthDomain:    deviceCodeServer.URL,
		ClientID:      "mock-client-id",
		AegisEndpoint: signerServer.URL,
		KeyOutputPath: t.TempDir(),
		TTL:           1 * time.Hour,
	}

	err := run(cfg)
	assert.NoError(t, err)
}

func TestRun_InvalidDeviceCode(t *testing.T) {
	// device code server returns 400 Bad Request
	deviceCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer deviceCodeServer.Close()

	signerServer := mockSignerServer()
	defer signerServer.Close()

	cfg := ClientConfig{
		AuthDomain:    deviceCodeServer.URL,
		ClientID:      "mock-client-id",
		AegisEndpoint: signerServer.URL,
		KeyOutputPath: t.TempDir(),
		TTL:           1 * time.Hour,
	}

	err := run(cfg)
	assert.Error(t, err)
}
func TestRun_SignError(t *testing.T) {
	// signer server returns 500 Internal Server Error
	signerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer signerServer.Close()

	deviceCodeServer := mockDeviceCodeServer()
	defer deviceCodeServer.Close()

	configPathFlag = t.TempDir()

	cfg := ClientConfig{
		AuthDomain:    deviceCodeServer.URL,
		ClientID:      "mock-client-id",
		AegisEndpoint: signerServer.URL,
		KeyOutputPath: t.TempDir(),
		TTL:           1 * time.Hour,
	}

	err := run(cfg)
	assert.Error(t, err)
}

func TestRun_WriteKeyToFileError(t *testing.T) {
	// Create a temporary directory and remove it to simulate a write error
	tempDir := t.TempDir()
	if err := os.Remove(tempDir); err != nil {
		t.Fatalf("failed to remove temp dir: %v", err)
	}

	// signer server returns 500 Internal Server Error
	signerServer := mockSignerServer()
	defer signerServer.Close()

	deviceCodeServer := mockDeviceCodeServer()
	defer deviceCodeServer.Close()

	configPathFlag = t.TempDir()

	cfg := ClientConfig{
		AuthDomain:    deviceCodeServer.URL,
		ClientID:      "mock-client-id",
		AegisEndpoint: signerServer.URL,
		KeyOutputPath: tempDir, // use the removed path here
		TTL:           1 * time.Hour,
	}

	err := run(cfg)
	assert.Error(t, err)
}
