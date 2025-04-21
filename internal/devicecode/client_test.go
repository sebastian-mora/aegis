package devicecode_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sebastian-mora/aegis/internal/devicecode"
	"github.com/stretchr/testify/assert"
)

func TestRequestDeviceCode_Success(t *testing.T) {
	// Setup mock server
	handler := http.NewServeMux()
	handler.HandleFunc("/application/o/device/", func(w http.ResponseWriter, r *http.Request) {
		// Validate input
		assert.Equal(t, r.Method, "POST")
		assert.Equal(t, r.URL.Path, "/application/o/device/")
		assert.Equal(t, r.FormValue("client_id"), "test-client-id")
		assert.Equal(t, r.FormValue("scope"), "openid")

		// Mock the response
		response := devicecode.DeviceCodeRequestResponse{
			DeviceCode:       "device_code_123",
			UserCode:         "user_code_456",
			VerfificationURI: "http://example.com",
			Interval:         5,
			ExpiresIn:        300,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Initialize the DeviceCodeAuthentik object
	dc := devicecode.NewDeviceCodeAuthentik(server.URL, "test-client-id", "openid")

	// Call RequestDeviceCode
	resp, err := dc.RequestDeviceCode()

	// Check if the response is as expected
	assert.NoError(t, err)
	assert.Equal(t, "device_code_123", resp.DeviceCode)
	assert.Equal(t, "user_code_456", resp.UserCode)
	assert.Equal(t, "http://example.com", resp.VerfificationURI)
	assert.Equal(t, 5, resp.Interval)
	assert.Equal(t, 300, resp.ExpiresIn)
}

func TestRequestDeviceCode_Fail(t *testing.T) {
	// Setup mock server to return an error response
	handler := http.NewServeMux()
	handler.HandleFunc("/application/o/device/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	dc := devicecode.NewDeviceCodeAuthentik(server.URL, "test-client-id", "openid")

	// Call RequestDeviceCode and expect error
	_, err := dc.RequestDeviceCode()

	// Check if the error is returned
	assert.Error(t, err)
}

func TestPollDeviceCode_Success(t *testing.T) {
	// Mock the response for the polling request
	handler := http.NewServeMux()
	handler.HandleFunc("/application/o/token/", func(w http.ResponseWriter, r *http.Request) {
		// Mock the token response on the first poll
		response := devicecode.DeviceCodeTokenResponse{
			AccessToken: "access_token_123",
			IdToken:     "id_token_456",
			TokenType:   "bearer",
			ExpiresIn:   3600,
			Scope:       "openid",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	dc := devicecode.NewDeviceCodeAuthentik(server.URL, "test-client-id", "openid")

	// Test polling with context
	deviceCodeResp := &devicecode.DeviceCodeRequestResponse{
		DeviceCode: "device_code_123",
		Interval:   1, // set to 1 second for quick polling
	}

	// Create a timeout context for polling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Call PollDeviceCode
	tokenResp, err := dc.PollDeviceCode(ctx, *deviceCodeResp)

	// Check if no error occurred and the expected token response was received
	assert.NoError(t, err)
	assert.Equal(t, "access_token_123", tokenResp.AccessToken)
	assert.Equal(t, "id_token_456", tokenResp.IdToken)
}

func TestPollDeviceCode_Cancelled(t *testing.T) {
	// Setup mock server to simulate a pending authorization
	handler := http.NewServeMux()
	handler.HandleFunc("/application/o/token/", func(w http.ResponseWriter, r *http.Request) {
		// Return a "authorization_pending" error to simulate polling
		response := struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}{
			Error:            "authorization_pending",
			ErrorDescription: "The authorization is still pending.",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	dc := devicecode.NewDeviceCodeAuthentik(server.URL, "test-client-id", "openid")

	// Test polling with context cancellation
	deviceCodeResp := &devicecode.DeviceCodeRequestResponse{
		DeviceCode: "device_code_123",
		Interval:   1, // quick polling interval
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dc.PollDeviceCode(ctx, *deviceCodeResp)

	// Assert that polling finished due to context cancellation
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestPollDeviceCode_ServerError(t *testing.T) {
	// Setup mock server to return an error response
	handler := http.NewServeMux()
	handler.HandleFunc("/application/o/token/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	dc := devicecode.NewDeviceCodeAuthentik(server.URL, "test-client-id", "openid")

	// Test polling with context
	deviceCodeResp := &devicecode.DeviceCodeRequestResponse{
		DeviceCode: "device_code_123",
		Interval:   1, // quick polling interval
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dc.PollDeviceCode(ctx, *deviceCodeResp)

	// Assert that an error occurred
	assert.Error(t, err)
}
