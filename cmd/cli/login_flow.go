package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"

	"golang.org/x/oauth2"
)

// Authenticator interface for authentication flows
// DeviceCodeAuthenticator and PKCEAuthenticator implement this interface
type Authenticator interface {
	Authenticate(cfg ClientConfig) (*oauth2.Token, error)
}

// PKCEAuthenticator implements the Authenticator interface for local callback (PKCE) flow.
type PKCEAuthenticator struct {
}

func (a *PKCEAuthenticator) Authenticate(cfg ClientConfig) (*oauth2.Token, error) {
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	listener, redirectURL, err := startLocalListener()
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	oauthCfg := buildOAuth2Config(cfg, redirectURL)
	state := generateState()
	authURL := buildAuthURL(oauthCfg, state, codeChallenge)

	fmt.Println("To authenticate, visit this URL:")
	fmt.Printf("  %s\n", authURL)
	fmt.Println()
	fmt.Println("Waiting for callback...")
	fmt.Println()

	codeCh := make(chan string)
	server := &http.Server{}
	registerCallbackHandler(state, codeCh)

	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
	defer server.Close()

	code := <-codeCh

	// Exchange code for token
	token, err := oauthCfg.Exchange(context.Background(), code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	fmt.Println("Token acquired successfully")
	return token, nil
}

func startLocalListener() (net.Listener, string, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", fmt.Errorf("failed to start listener: %w", err)
	}
	redirectURL := "http://" + listener.Addr().String() + "/callback"
	return listener, redirectURL, nil
}

func buildOAuth2Config(cfg ClientConfig, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    cfg.ClientID,
		RedirectURL: redirectURL,
		Scopes:      []string{cfg.Scope},
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthDomain + "/application/o/authorize/",
			TokenURL: cfg.AuthDomain + "/application/o/token/",
		},
	}
}

func buildAuthURL(oauthCfg *oauth2.Config, state, codeChallenge string) string {
	return oauthCfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func registerCallbackHandler(state string, codeCh chan<- string) {
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if r.URL.Path != "/callback" || query.Get("state") != state {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		code := query.Get("code")
		if code == "" {
			http.Error(w, "No code in request", http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, "Authentication successful. You may now close this tab.")
		codeCh <- code
	})
}

func generatePKCE() (codeVerifier, codeChallenge string, err error) {
	verifierBytes := make([]byte, 32)
	if _, err = rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return codeVerifier, codeChallenge, nil
}

func generateState() string {
	state := make([]byte, 16)
	if _, err := rand.Read(state); err != nil {
		log.Fatalf("failed to generate state: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(state)

}

// DeviceCodeAuthenticator implements the Authenticator interface for device code flow.
type DeviceCodeAuthenticator struct{}

func (a *DeviceCodeAuthenticator) Authenticate(cfg ClientConfig) (*oauth2.Token, error) {
	oauthCfg := &oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: cfg.AuthDomain + "/application/o/device/",
			TokenURL:      cfg.AuthDomain + "/application/o/token/",
		},
		Scopes: []string{cfg.Scope},
	}
	ctx := context.Background()

	// Request device code
	response, err := oauthCfg.DeviceAuth(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Printf("To authenticate, visit: %s\n", response.VerificationURIComplete)

	// Poll for the token
	token, err := oauthCfg.DeviceAccessToken(ctx, response)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %v", err)
	}
	return token, nil
}
