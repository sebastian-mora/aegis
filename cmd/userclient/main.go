package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	devicecode "github.com/sebastian-mora/aegis/internal/device_code"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

type ClientConfig struct {
	AuthDomain    string
	ClientID      string
	AegisEndpoint string
	Scope         string
}

var keyPath = filepath.Join(os.Getenv("HOME"), ".ssh")

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}

func loadConfig(configPath string) (*ClientConfig, error) {
	godotenv.Load(configPath)

	config := &ClientConfig{
		AuthDomain:    os.Getenv("AUTH_DOMAIN"),
		ClientID:      os.Getenv("CLIENT_ID"),
		AegisEndpoint: os.Getenv("AEGIS_ENDPOINT"),
		Scope:         "openid email sign:user_key",
	}
	if config.AuthDomain == "" || config.ClientID == "" || config.AegisEndpoint == "" {
		return nil, fmt.Errorf("missing required environment variables")
	}
	return config, nil
}

func GenerateSSHKeyPair() (string, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("key generation failed: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("ssh signer creation failed: %w", err)
	}

	publicKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: priv.Seed(),
	})

	return publicKey, string(privateKeyPEM), nil
}

func WriteKeyToFile(name, key string) error {
	err := os.WriteFile(filepath.Join(keyPath, name), []byte(key), 0600)
	if err != nil {
		return fmt.Errorf("write key to file failed: %w", err)
	}
	return nil
}

func main() {
	// Load config from ~/.ssh/aegis_config

	configPath := filepath.Join(os.Getenv("HOME"), ".ssh", "aegis_config")

	config, err := loadConfig(configPath)

	if err != nil {
		fatal("Failed to load configuration from ~/.ssh/aegis_config: %v", err)
	}

	fmt.Println("🔐 Aegis Signer CLI")

	deviceCodeClient := devicecode.NewDeviceCodeAuthentik(config.AuthDomain, config.ClientID, config.Scope)
	oauthResp, err := deviceCodeClient.RequestDeviceCode()
	if err != nil {
		fatal("Failed to initiate device code request: %v", err)
	}

	fmt.Printf("📲 To authenticate, visit: %s\n", oauthResp.VerfificationURI)

	fmt.Println("⏳ Waiting for login...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(oauthResp.ExpiresIn)*time.Second)
	defer cancel()

	tokenResp, err := deviceCodeClient.PollDeviceCode(ctx, *oauthResp)
	if err != nil {
		fatal("❌ Authentication failed: %v", err)
	}
	idToken := tokenResp.IdToken

	fmt.Println("🔧 Generating a new SSH key pair...")
	pubKey, privKey, _ := GenerateSSHKeyPair()

	signedPubKey, err := signer.NewAegisClient(config.AegisEndpoint, idToken).SubmitPublicKey(pubKey)

	if err != nil {
		fatal("❌ Failed to submit public key: %v", err)
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

	fmt.Printf("✅ SSH certificate saved to: ~/.ssh/aegis-cert.pub\n")
	// fmt.Println("🔍 Inspecting SSH certificate...")

	// out, err := exec.Command("ssh-keygen", "-L", "-f", filepath.Join(keyPath, "aegis-cert.pub")).CombinedOutput()
	// if err != nil {
	// 	fmt.Println("⚠️  Failed to inspect certificate:", err)
	// }
	// fmt.Println(string(out))
}
