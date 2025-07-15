package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sebastian-mora/aegis/internal/signer"
)

var (
	verboseFlag       bool
	authDomainFlag    string
	clientIDFlag      string
	aegisEndpointFlag string
	configPathFlag    string
	keyOutputPathFlag string
	ttlFlag           string
	deviceCodeFlag    bool
)

func initFlags() {
	flag.StringVar(&authDomainFlag, "auth-url", "", "URL to the authentication server")
	flag.StringVar(&clientIDFlag, "client-id", "", "Client ID for the authentication server")
	flag.StringVar(&aegisEndpointFlag, "aegis-endpoint", "", "Aegis endpoint")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
	flag.StringVar(&configPathFlag, "config", filepath.Join(os.Getenv("HOME"), ".config/aegis/config"), "Path to the configuration file")
	flag.StringVar(&keyOutputPathFlag, "key-output-path", filepath.Join(os.Getenv("HOME"), ".ssh"), "Path to save the generated keys")
	flag.StringVar(&ttlFlag, "ttl", "24h", "Time to live for the signed key")
	flag.Parse()
}

func loadClientConfig() (ClientConfig, error) {
	cfg := loadConfig(configPathFlag)

	// Override with CLI flags if provided
	if authDomainFlag != "" {
		cfg.AuthDomain = authDomainFlag
	}
	if clientIDFlag != "" {
		cfg.ClientID = clientIDFlag
	}
	if aegisEndpointFlag != "" {
		cfg.AegisEndpoint = aegisEndpointFlag
	}
	if keyOutputPathFlag != "" {
		cfg.KeyOutputPath = keyOutputPathFlag
	}
	if ttlFlag != "" {
		parsedTTL, err := time.ParseDuration(ttlFlag)
		if err != nil {
			return cfg, fmt.Errorf("invalid TTL: %w", err)
		}
		cfg.TTL = parsedTTL
	}

	if cfg.AuthDomain == "" || cfg.ClientID == "" || cfg.AegisEndpoint == "" {
		return cfg, fmt.Errorf("missing required config values (auth-url, client-id, aegis-endpoint)")
	}

	return cfg, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}

func WriteKeyToFile(path, key string) error {
	return os.WriteFile(path, []byte(key), 0600)
}

func getAuthenticator(deviceCode bool) Authenticator {
	if deviceCode {
		return &DeviceCodeAuthenticator{}
	}
	return &PKCEAuthenticator{}
}

func run(cfg ClientConfig) error {
	fmt.Println("🔐 Aegis Signer CLI")

	tokenPath := filepath.Join(filepath.Dir(configPathFlag), "token.json")
	token, err := LoadToken(tokenPath)
	auth := getAuthenticator(deviceCodeFlag)

	if err != nil || token == nil || token.Expiry.Before(time.Now()) {
		token, err = auth.Authenticate(cfg)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		// Save the token for future use
		if err := SaveToken(tokenPath, token); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}
	}

	claims, _ := ParseAccessToken(token.AccessToken)
	fmt.Printf("👤 User authenticated: %s\n", claims.Name)

	fmt.Println("🔑 Generating Ed25519 key pair...")
	pubKey, privKey, err := signer.NewSSHKeyPair(signer.Ed25519)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	fmt.Println("🚀 Submitting public key to Aegis for signing...")
	signedPubKey, err := submitPublicKeyForSigning(cfg, token.AccessToken, pubKey)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	err = saveKeyPair(cfg, pubKey, string(signedPubKey), privKey)
	if err != nil {
		return fmt.Errorf("failed to save key pair: %w", err)
	}

	fmt.Printf("\tPublic key saved to: %s/aegis.pub\n", cfg.KeyOutputPath)
	fmt.Printf("\tPrivate key saved to: %s/aegis\n", cfg.KeyOutputPath)
	fmt.Printf("\tCertificate saved to: %s/aegis-cert.pub\n", cfg.KeyOutputPath)

	return nil
}

func saveKeyPair(cfg ClientConfig, pubKey, signedPubKey, privKey string) error {
	files := map[string]string{
		"aegis.pub":      pubKey,
		"aegis":          privKey,
		"aegis-cert.pub": signedPubKey,
	}

	for name, content := range files {
		path := filepath.Join(cfg.KeyOutputPath, name)
		if err := WriteKeyToFile(path, content); err != nil {
			return fmt.Errorf("failed to write %s: %v", name, err)
		}
	}

	return nil
}

func submitPublicKeyForSigning(cfg ClientConfig, token string, pubKey string) ([]byte, error) {
	client := signer.NewAegisClient(cfg.AegisEndpoint, token)
	return client.SubmitPublicKey(signer.PublicKeySignRequest{
		PublicKey: pubKey,
		TTL:       cfg.TTL,
	})
}

func main() {
	initFlags()

	if err := createAegisConfigDir(); err != nil {
		fatalf("failed to create config directory: %v", err)
	}

	cfg, err := loadClientConfig()
	if err != nil {
		fatalf(err.Error())
	}

	if verboseFlag {
		fmt.Printf("Using configuration: %+v\n", cfg)
	}

	if err := run(cfg); err != nil {
		fatalf(err.Error())
	}
}
