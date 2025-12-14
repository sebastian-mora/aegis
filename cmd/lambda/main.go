package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/handler"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

func main() {
	// Load environment variables
	secretName := os.Getenv("USER_CA_KEY_NAME")
	jmesPathExpression := os.Getenv("JSME_PATH_EXPRESSION")
	dynamoDbTableName := os.Getenv("DYNAMO_DB_TABLE")

	// Initialize with a short timeout for setup operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a new AWS session
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slog.Error("fatal: unable to load AWS config", "error", err)
		os.Exit(1)
	}

	// Load the certificate signer from AWS Secrets Manager
	caCert, err := GetSecretFromSecretsManager(ctx, cfg, secretName)
	if err != nil {
		slog.Error("fatal: failed to load certificate signer", "error", err)
		os.Exit(1)
	}

	// Create a new SSH signer from the private key
	caCertSigner, err := ssh.ParsePrivateKey([]byte(caCert))
	if err != nil {
		slog.Error("fatal: failed to parse private key", "error", err)
		os.Exit(1)
	}

	// Validate JMESPath expression is provided
	if jmesPathExpression == "" {
		slog.Error("fatal: JMESPath expression not provided in environment")
		os.Exit(1)
	}

	slog.Info("initializing signer", "jmespath_expression", jmesPathExpression)

	// Create JMESPathPrincipalMapper
	principalMapper, err := signer.NewJMESPathPrincipalMapper(jmesPathExpression)
	if err != nil {
		slog.Error("fatal: failed to create JMESPathPrincipalMapper", "error", err)
		os.Exit(1)
	}

	// Initialize the SSH signer
	sshSigner := signer.NewSSHCASigner(caCertSigner)

	// Initialize the audit writer
	dynmoDbAuditStore, err := audit.NewDynamoDbAuditStore(dynamoDbTableName)
	if err != nil {
		slog.Error("fatal: failed to create DynamoDB audit store", "error", err)
		os.Exit(1)
	}

	// Create the signer handler with injected dependencies
	signerHandler := handler.NewSignerHandler(sshSigner, principalMapper, dynmoDbAuditStore)

	// Create the API Gateway handler that delegates to the signer
	apigwHandler := NewAPIGatewayHandler(signerHandler)

	// Start the Lambda function with the API Gateway handler
	lambda.Start(apigwHandler.Handle)
}
