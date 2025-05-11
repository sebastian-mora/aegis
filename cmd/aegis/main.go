package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/oauth2"
)

var (
	verboseFlag       bool
	authDomainFlag    string
	clientIDFlag      string
	aegisEndpointFlag string
	configPathFlag    string
	keyOutputPathFlag string
	ttlFlag           string
	config            ClientConfig
)

func init() {

	//
	err := createAegisConfigDir()
	if err != nil {
		fatal("Failed to create config directory: %v", err)
	}

	// Parse flags
	flag.StringVar(&authDomainFlag, "auth-url", "", "Url to the authentication server")
	flag.StringVar(&clientIDFlag, "client-id", "", "Client ID for the authentication server")
	flag.StringVar(&aegisEndpointFlag, "aegis-endpoint", "", "Aegis endpoint")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
	flag.StringVar(&configPathFlag, "config", filepath.Join(os.Getenv("HOME"), ".config/aegis"), "Path to the configuration file")
	flag.StringVar(&keyOutputPathFlag, "key-output-path", filepath.Join(os.Getenv("HOME"), ".ssh"), "Path to save the generated keys")
	flag.StringVar(&ttlFlag, "ttl", "24h", "Time to live for the signed key")
	flag.Parse()

	// Load environment variables
	config = loadConfig()

	// Override with command-line flags if provided
	if authDomainFlag != "" {
		config.AuthDomain = authDomainFlag
	}
	if clientIDFlag != "" {
		config.ClientID = clientIDFlag
	}
	if aegisEndpointFlag != "" {
		config.AegisEndpoint = aegisEndpointFlag
	}
	if keyOutputPathFlag != "" {
		config.KeyOutputPath = keyOutputPathFlag
	}
	if ttlFlag != "" {
		parsedTTL, err := time.ParseDuration(ttlFlag)
		if err != nil {
			fatal("Error parsing -ttl: %v", err)
		}
		config.TTL = parsedTTL
	}

	// Check for required configuration values
	if config.AuthDomain == "" || config.ClientID == "" || config.AegisEndpoint == "" {
		fatal("Missing required configuration values. Please provide them via flags or in the environment.")
	}

	// Optional: Print verbose output
	if verboseFlag {
		fmt.Printf("Using configuration: %+v\n", config)
	}
}

func WriteKeyToFile(name, key string) error {
	err := os.WriteFile(filepath.Join(config.KeyOutputPath, name), []byte(key), 0600)
	if err != nil {
		return fmt.Errorf("write key to file failed: %w", err)
	}
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}

func authenticateUser() *oauth2.Token {

	// Create a new OAuth2 config
	oauthConfig := &oauth2.Config{
		ClientID: config.ClientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: config.AuthDomain + "/application/o/device/",
			TokenURL:      config.AuthDomain + "/application/o/token/",
		},
		Scopes: []string{config.Scope},
	}

	// Request a token
	ctx := context.Background()
	token, err := RequestDeviceCode(ctx, oauthConfig)
	if err != nil {
		fatal("Failed to request device code: %v", err)
	}

	return token
}

func saveKeyPair(pubKey, signedPubKey, privKey string) {

	// Save the keys to files
	if err := WriteKeyToFile("aegis.pub", pubKey); err != nil {
		fatal("Failed to write public key to file: %v", err)
	}
	if err := WriteKeyToFile("aegis", privKey); err != nil {
		fatal("Failed to write private key to file: %v", err)
	}
	if err := WriteKeyToFile("aegis-cert.pub", string(signedPubKey)); err != nil {
		fatal("Failed to write certificate to file: %v", err)
	}
}

func submitPublicKeyForAegisSigning(accessToken string, request signer.PublicKeySignRequest) ([]byte, error) {
	// Create a new Aegis client
	aegisClient := signer.NewAegisClient(config.AegisEndpoint, accessToken)

	// Submit the public key to Aegis for signing
	signedPubKey, err := aegisClient.SubmitPublicKey(request)
	if err != nil {
		return nil, err
	}

	return signedPubKey, nil
}

func main() {
	fmt.Println("🔐 Aegis Signer CLI")

	// Get or authenticate the user to get an access token
	oauthToken, err := LoadToken(configPathFlag + "/token.json")
	if err != nil {
		fatal("Failed to load access token: %v", err)
	}

	// If we failed to load a cached token or it's expired, reauth
	if oauthToken == nil || oauthToken.Expiry.Before(time.Now()) {
		oauthToken = authenticateUser()
		if err := SaveToken(configPathFlag+"/token.json", oauthToken); err != nil {
			fatal("Failed to save access token: %v", err)
		}
	}

	tokenClaims, _ := ParseAccessToken(oauthToken.AccessToken)
	fmt.Printf("👤 User authenticated: %s\n", tokenClaims.Name)

	// Generate a new Ed25519 key pair
	fmt.Println("🔑 Generating Ed25519 key pair...")

	pubKey, privKey, err := signer.NewSSHKeyPair(signer.Ed25519)
	if err != nil {
		fatal("Failed to generate key pair: %v", err)
	}

	// Submit the public key to Aegis for signing
	fmt.Println("🚀 Submitting public key to Aegis for signing...")

	signedPubKey, err := submitPublicKeyForAegisSigning(oauthToken.AccessToken, signer.PublicKeySignRequest{
		PublicKey: pubKey,
		TTL:       config.TTL,
	})
	if err != nil {
		fatal("Failed to submit public key for signing: %v", err)
	}

	// Save the keys to files
	saveKeyPair(pubKey, string(signedPubKey), privKey)
	fmt.Printf("\tPublic key saved to: %s/aegis.pub\n", config.KeyOutputPath)
	fmt.Printf("\tPrivate key saved to: %s/aegis\n", config.KeyOutputPath)
	fmt.Printf("\tCertificate saved to: %s/aegis-cert.pub\n", config.KeyOutputPath)

}
