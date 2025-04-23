package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

type ClientConfig struct {
	AuthDomain    string
	ClientID      string
	AegisEndpoint string
	Scope         string
	KeyOutputPath string
}

func createAegisConfigDir() error {
	configDir := os.Getenv("HOME") + "/.config/aegis"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}
	return nil
}

func loadConfig() ClientConfig {

	// if the config file exists in the config directory, load it
	configFile := filepath.Join(os.Getenv("HOME"), ".config/aegis", "config")
	if _, err := os.Stat(configFile); err == nil {
		godotenv.Load(configFile)
	}

	return ClientConfig{
		AuthDomain:    getEnv("AUTH_DOMAIN", ""),
		ClientID:      getEnv("CLIENT_ID", ""),
		AegisEndpoint: getEnv("AEGIS_ENDPOINT", ""),
		Scope:         getEnv("SCOPE", "openid email profile sign:user_key"),
		KeyOutputPath: getEnv("KEY_OUTPUT_PATH", filepath.Join(os.Getenv("HOME"), ".ssh")),
	}
}

// Helper function to get environment variables with a default value
func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}
