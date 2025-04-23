package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/oauth2"
)

type ClientConfig struct {
	AuthDomain    string
	ClientID      string
	AegisEndpoint string
	Scope         string
	KeyOutputPath string
}

var (
	verboseFlag       bool
	authDomainFlag    string
	clientIDFlag      string
	aegisEndpointFlag string
	configPathFlag    string
	keyOutputPathFlag string
	config            ClientConfig
)

func init() {
	flag.StringVar(&authDomainFlag, "auth-url", "", "Url to the authentication server")
	flag.StringVar(&clientIDFlag, "client-id", "", "Client ID for the authentication server")
	flag.StringVar(&aegisEndpointFlag, "aegis-endpoint", "", "Aegis endpoint")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
	flag.StringVar(&configPathFlag, "config", filepath.Join(os.Getenv("HOME"), ".config/aegis", "config"), "Path to the configuration file")
	flag.StringVar(&keyOutputPathFlag, "key-output-path", filepath.Join(os.Getenv("HOME"), ".ssh"), "Path to save the generated keys")
	flag.Parse()

	fileConfig, err := loadConfig(configPathFlag)
	if err != nil {
		log.Default().Printf("Failed to load configuration from %s: %v\n", configPathFlag, err)
	}

	// Override config with command line flags if provided
	if authDomainFlag != "" {
		fileConfig.AuthDomain = authDomainFlag
	}
	if clientIDFlag != "" {
		fileConfig.ClientID = clientIDFlag
	}
	if aegisEndpointFlag != "" {
		fileConfig.AegisEndpoint = aegisEndpointFlag
	}
	if keyOutputPathFlag != "" {
		fileConfig.KeyOutputPath = keyOutputPathFlag
	}

	// Set the config
	config = *fileConfig
	if verboseFlag {
		fmt.Printf("Using configuration: %+v\n", config)
	}
	if config.AuthDomain == "" || config.ClientID == "" || config.AegisEndpoint == "" {
		fatal("Missing required configuration values. Please provide them via flags or in the config file.")
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

func getAccessToken() string {
	accessTokenFilePath := filepath.Join(config.KeyOutputPath, "aegis_access_token")

	// Check if the access token file exists
	if _, err := os.Stat(accessTokenFilePath); err == nil {
		// Read the access token from the file
		data, err := os.ReadFile(accessTokenFilePath)
		if err != nil {
			fatal("Failed to read access token file: %v", err)
		}
		accessToken := string(data)

		// Check if the access token is expired
		tokenClaims, err := ParseAccessToken(accessToken)
		if err != nil {
			fatal("Failed to parse access token: %v", err)
		}
		if tokenClaims.Exp < time.Now().Unix() {
			accessToken = ""
		}

		return accessToken
	}
	return ""
}

func authenticateUser() string {

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

	return token.AccessToken
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

func submitPublicKeyForAegisSigning(accessToken string, pubKey string) ([]byte, error) {
	// Create a new Aegis client
	aegisClient := signer.NewAegisClient(config.AegisEndpoint, accessToken)

	// Submit the public key to Aegis for signing
	signedPubKey, err := aegisClient.SubmitPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to submit public key: %w", err)
	}

	return signedPubKey, nil
}

func saveAccessToken(accessToken string) {
	// Save the access token to a file
	accessTokenFilePath := filepath.Join(config.KeyOutputPath, "aegis_access_token")
	if err := os.WriteFile(accessTokenFilePath, []byte(accessToken), 0600); err != nil {
		fatal("Failed to write access token to file: %v", err)
	}
}

func main() {
	fmt.Println("🔐 Aegis Signer CLI")

	// Create the config directory if it doesn't exist
	if err := createAegisConfigDir(); err != nil {
		fatal("Failed to create config directory: %v", err)
	}

	// Get or authenticate the user to get an access token
	accessToken := getAccessToken()
	if accessToken == "" {
		fmt.Println("🔄 Access token is expired. Re-authenticating...")
		accessToken = authenticateUser()
	}

	tokenClaims, _ := ParseAccessToken(accessToken)
	fmt.Printf("👤 User authenticated: %s\n", tokenClaims.Name)

	// Generate a new Ed25519 key pair
	fmt.Println("🔑 Generating Ed25519 key pair...")

	pubKey, privKey, err := signer.NewSSHKeyPair(signer.Ed25519)
	if err != nil {
		fatal("Failed to generate key pair: %v", err)
	}

	// Submit the public key to Aegis for signing
	fmt.Println("🚀 Submitting public key to Aegis for signing...")

	signedPubKey, err := submitPublicKeyForAegisSigning(accessToken, pubKey)
	if err != nil {
		fatal("Failed to submit public key for signing: %v", err)
	}

	// Save the keys to files
	saveKeyPair(pubKey, string(signedPubKey), privKey)
	fmt.Printf("\tPublic key saved to: %s/aegis.pub\n", config.KeyOutputPath)
	fmt.Printf("\tPrivate key saved to: %s/aegis\n", config.KeyOutputPath)
	fmt.Printf("\tCertificate saved to: %s/aegis-cert.pub\n", config.KeyOutputPath)

	// Save the access token
	saveAccessToken(accessToken)

}
