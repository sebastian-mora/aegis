package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

const envKMSKeyID = "KMS_KEY_ID"

func Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	kmsKeyId := os.Getenv(envKMSKeyID)
	if kmsKeyId == "" {
		slog.Error("missing required env var", "var", envKMSKeyID)
		os.Exit(1)
	}

	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		slog.Error("failed to load AWS config", "error", err)
		return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "Internal Server Error"}, nil
	}

	// Create KMS client
	kmsClient := kms.NewFromConfig(awsCfg)

	// Reuse the cert signing to parse the public key
	certSigner, err := signer.NewSSHCertSigner(context.TODO(), kmsClient, kmsKeyId)
	if err != nil {
		slog.Error("failed to create SSH cert signer", "error", err)
		return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "Internal Server Error"}, nil
	}

	// Return the public key in authorized_keys format
	pubKeyBytes := ssh.MarshalAuthorizedKey(certSigner.PublicKey())
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(pubKeyBytes),
		Headers: map[string]string{
			"Content-Type": "text/plain",
		},
	}, nil

}

func main() {
	lambda.Start(Handle)
}
