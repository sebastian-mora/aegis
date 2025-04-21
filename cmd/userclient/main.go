package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"github.com/sebastian-mora/aegis/internal/devicecode"
	"github.com/sebastian-mora/aegis/internal/signer"
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
	flag.StringVar(&authDomainFlag, "auth-url", "", "URL to the authentication server")
	flag.StringVar(&clientIDFlag, "client-id", "", "Client ID for the authentication server")
	flag.StringVar(&aegisEndpointFlag, "aegis-endpoint", "", "Aegis endpoint")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
	flag.StringVar(&configPathFlag, "config", filepath.Join(os.Getenv("HOME"), ".ssh", "aegis_config"), "Path to the configuration file")
	flag.StringVar(&keyOutputPathFlag, "key-output-path", filepath.Join(os.Getenv("HOME"), ".ssh"), "Path to save the generated keys")
	flag.Parse()

	// Load the configuration file
	fileConfig, err := loadConfig(configPathFlag)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to load configuration from %s: %v", configPathFlag, err))
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

func loadConfig(configPath string) (*ClientConfig, error) {
	// Load environment variables from the config path
	err := godotenv.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}

	config := &ClientConfig{
		AuthDomain:    os.Getenv("AUTH_DOMAIN"),
		ClientID:      os.Getenv("CLIENT_ID"),
		AegisEndpoint: os.Getenv("AEGIS_ENDPOINT"),
		Scope:         "openid email profile sign:user_key",
	}
	if config.AuthDomain == "" || config.ClientID == "" || config.AegisEndpoint == "" {
		return nil, fmt.Errorf("missing required environment variables")
	}
	return config, nil
}

func WriteKeyToFile(name, key string) error {
	// Ensure the output path exists
	err := os.MkdirAll(config.KeyOutputPath, 0700)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write the key to file
	err = os.WriteFile(filepath.Join(config.KeyOutputPath, name), []byte(key), 0600)
	if err != nil {
		return fmt.Errorf("write key to file failed: %w", err)
	}
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	fmt.Println("🔐 Aegis Signer CLI")

	var accessToken string
	accessTokenFilePath := filepath.Join(config.KeyOutputPath, "aegis_access_token")

	// Check if the access token file exists
	if _, err := os.Stat(accessTokenFilePath); err == nil {
		// Read the access token from the file
		data, err := os.ReadFile(accessTokenFilePath)
		if err != nil {
			fatal("Failed to read access token file: %v", err)
		}
		accessToken = string(data)

		// Check if the access token is expired
		tokenClaims, err := devicecode.ParseAccessToken(accessToken)
		if err != nil {
			fatal("Failed to parse access token: %v", err)
		}
		if tokenClaims.Exp < time.Now().Unix() {
			fmt.Println("Access token is expired. Re-authenticating...")
			accessToken = "" // Reset token and re-authenticate
		}
	}

	// If the access token is not available or expired, authenticate using the device code flow
	if accessToken == "" {
		deviceCodeClient := devicecode.NewDeviceCodeAuthentik(config.AuthDomain, config.ClientID, config.Scope)
		oauthResp, err := deviceCodeClient.RequestDeviceCode()
		if err != nil {
			fatal("Failed to initiate device code request: %v", err)
		}

		fmt.Printf("📲 To authenticate, visit: %s\n", oauthResp.VerfificationURI)
		fmt.Println("\tWaiting for login...")

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(oauthResp.ExpiresIn)*time.Second)
		defer cancel()

		tokenResp, err := deviceCodeClient.PollDeviceCode(ctx, *oauthResp)
		if err != nil {
			fatal("❌ Authentication failed: %v", err)
		}
		accessToken = tokenResp.AccessToken
	}

	// Parse the access token claims
	tokenClaims, _ := devicecode.ParseAccessToken(accessToken)
	fmt.Printf("👤 User authenticated: %s\n", tokenClaims.Name)

	// Generate SSH key pair
	fmt.Println("🔧 Generating a new SSH key pair...")
	pubKey, privKey, err := signer.NewEd25519KeyPair()
	if err != nil {
		fatal("❌ Key generation failed: %v", err)
	}

	// Sign the public key with Aegis
	signedPubKey, err := signer.NewAegisClient(config.AegisEndpoint, accessToken).SubmitPublicKey(pubKey)
	if err != nil {
		fatal("Failed to submit public key: %v", err)
	}
	fmt.Println("✅ Public key signed successfully by Aegis!")

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

	// Save the access token to a file
	if err := os.WriteFile(accessTokenFilePath, []byte(accessToken), 0600); err != nil {
		fatal("Failed to write access token to file: %v", err)
	}

	fmt.Printf("\tSSH certificate saved to: %s\n", filepath.Join(config.KeyOutputPath, "aegis-cert.pub"))
}
