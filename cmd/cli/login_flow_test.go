package main

import (
	"strings"
	"testing"
)

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE returned error: %v", err)
	}
	if len(verifier) == 0 {
		t.Error("codeVerifier should not be empty")
	}
	if len(challenge) == 0 {
		t.Error("codeChallenge should not be empty")
	}
}

func TestGenerateState(t *testing.T) {
	state := generateState()
	if len(state) == 0 {
		t.Error("state should not be empty")
	}
}

func TestBuildOAuth2Config(t *testing.T) {
	cfg := ClientConfig{
		AuthDomain: "https://auth.example.com",
		ClientID:   "test-client-id",
		Scope:      "openid",
	}
	redirectURL := "http://localhost:1234/callback"
	ocfg := buildOAuth2Config(cfg, redirectURL)
	if ocfg.ClientID != cfg.ClientID {
		t.Errorf("expected ClientID %s, got %s", cfg.ClientID, ocfg.ClientID)
	}
	if ocfg.RedirectURL != redirectURL {
		t.Errorf("expected RedirectURL %s, got %s", redirectURL, ocfg.RedirectURL)
	}
	if ocfg.Endpoint.AuthURL == "" || ocfg.Endpoint.TokenURL == "" {
		t.Error("AuthURL and TokenURL should not be empty")
	}
}

func TestBuildAuthURL(t *testing.T) {
	cfg := ClientConfig{
		AuthDomain: "https://auth.example.com",
		ClientID:   "test-client-id",
		Scope:      "openid",
	}
	redirectURL := "http://localhost:1234/callback"
	ocfg := buildOAuth2Config(cfg, redirectURL)
	state := "teststate"
	challenge := "testchallenge"
	url := buildAuthURL(ocfg, state, challenge)
	if !strings.Contains(url, state) {
		t.Errorf("authURL should contain state")
	}
	if !strings.Contains(url, challenge) {
		t.Errorf("authURL should contain code_challenge")
	}
}
