package signer_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sebastian-mora/aegis/internal/signer"
)

func TestSubmitPublicKey(t *testing.T) {
	client := signer.NewAegisClient("http://localhost:8080", "test-token")

	// Create mock api
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "text/plain" {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}

		if string(body) != "pubkey" {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("signed-key"))
	}))
	defer server.Close()
	client.Endpoint = server.URL

	signedKey, err := client.SubmitPublicKey("pubkey")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(signedKey) != "signed-key" {
		t.Fatalf("expected signed key to be 'signed-key', got %s", signedKey)
	}

}
