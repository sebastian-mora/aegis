package client_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sebastian-mora/aegis/client"
)

func TestSubmitPublicKey_Valid(t *testing.T) {
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
		body, _ := io.ReadAll(r.Body)
		if string(body) != "pubkey" {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("signed-key"))
	}))
	defer server.Close()

	aegisClient := client.NewAegisClient(server.URL, "test-token")
	req := client.PublicKeySignRequest{
		PublicKey: "pubkey",
		TTL:       24 * time.Hour,
	}

	resp, err := aegisClient.SubmitPublicKey(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "signed-key" {
		t.Errorf("expected 'signed-key', got %q", resp)
	}
}

func TestSubmitPublicKey_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	aegisClient := client.NewAegisClient(server.URL, "") // No token
	req := client.PublicKeySignRequest{
		PublicKey: "pubkey",
		TTL:       24 * time.Hour,
	}

	_, err := aegisClient.SubmitPublicKey(req)
	if err == nil {
		t.Fatal("expected error for unauthorized request, got nil")
	}
}
