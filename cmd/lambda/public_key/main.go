package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/crypto/ssh"
)

const envKMSKeyID = "KMS_KEY_ID"

func main() {
	kmsKeyId := os.Getenv(envKMSKeyID)
	if kmsKeyId == "" {
		slog.Error("missing required env var", "var", envKMSKeyID)
		os.Exit(1)
	}

	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		slog.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	// Create KMS client
	kmsClient := kms.NewFromConfig(awsCfg)

	handler := &PublicKeyHandler{
		kmsClient: kmsClient,
		kmsKeyId:  kmsKeyId,
	}

	slog.Info("Public Key Lambda handler initialized successfully")
	lambda.Start(handler.Handle)
}

type PublicKeyHandler struct {
	kmsClient *kms.Client
	kmsKeyId  string
}

func (h *PublicKeyHandler) Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Get the public key from KMS
	pubKeyResp, err := h.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &h.kmsKeyId,
	})
	if err != nil {
		slog.Error("failed to get KMS public key", "error", err)
		return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "failed to get public key"}, nil
	}

	// Parse the DER-encoded public key
	pub, err := x509.ParsePKIXPublicKey(pubKeyResp.PublicKey)
	if err != nil {
		slog.Error("failed to parse public key", "error", err)
		return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "failed to parse public key"}, nil
	}

	// Convert to SSH public key format
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		slog.Error("failed to convert to SSH public key", "error", err)
		return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "failed to convert public key"}, nil
	}

	// Format as authorized_keys format (type base64-key comment)
	authorizedKey := fmt.Sprintf("%s aegis-ca", string(ssh.MarshalAuthorizedKey(sshPubKey)[:len(ssh.MarshalAuthorizedKey(sshPubKey))-1]))

	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/plain"},
		Body:       authorizedKey,
	}, nil
}
