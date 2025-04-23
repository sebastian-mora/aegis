package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func createAegisConfigDir() error {
	configDir := os.Getenv("HOME") + "/.config/aegis"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}
	return nil
}

func loadConfig(configPath string) (*ClientConfig, error) {
	godotenv.Load(configPath)

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
