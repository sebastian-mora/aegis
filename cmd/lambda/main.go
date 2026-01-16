package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/signer"
)

func main() {
	// Load environment variables
	kmsKeyID := os.Getenv("KMS_KEY_ID")
	jmesPathExpression := os.Getenv("JSME_PATH_EXPRESSION")
	dynamoDbTableName := os.Getenv("DYNAMO_DB_TABLE")

	// Initialize with a short timeout for setup operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a new AWS session
	cfg, err := config.LoadDefaultConfig(ctx)
	// Initialize all dependencies
	handler, err := initialize(context.Background())
	if err != nil {
		slog.Error("initialization failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Lambda handler initialized successfully")

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

	// Setup KMS Client
	kmsClient := kms.NewFromConfig(cfg)

	// Initialize the SSH signer
	sshSigner, err := signer.NewKMSSigner(ctx, kmsClient, kmsKeyID)
	if err != nil {
		slog.Error("fatal: failed to create KMSSigner", "error", err)
		os.Exit(1)
	}
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

	// Start Lambda runtime
	lambda.Start(handler.Handle)
}
