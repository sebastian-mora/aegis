package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/handler"
	"github.com/sebastian-mora/aegis/internal/principals"
	"github.com/sebastian-mora/aegis/internal/signer"
)

// Environment variable names
const (
	envKMSKeyID           = "KMS_KEY_ID"
	envJMESPathExpression = "JSME_PATH_EXPRESSION"
	envDynamoDBTable      = "DYNAMO_DB_TABLE"
)

// lambdaConfig holds configuration loaded from environment
type lambdaConfig struct {
	KmsKeyId           string
	JMESPathExpression string
	DynamoDBTableName  string
}

// InitOptions holds optional dependencies for initialization
type InitOptions struct {
	SSHCertificateSigner signer.SSHCertificateSigner
	PrincipalMapper      principals.PrincipalMapper
	AuditStore           audit.AuditWriter
}

type InitOption func(*InitOptions)

func WithSSHCertificateSigner(signer signer.SSHCertificateSigner) InitOption {
	return func(o *InitOptions) {
		o.SSHCertificateSigner = signer
	}
}

func WithPrincipalMapper(mapper principals.PrincipalMapper) InitOption {
	return func(o *InitOptions) {
		o.PrincipalMapper = mapper
	}
}

func WithAuditStore(store audit.AuditWriter) InitOption {
	return func(o *InitOptions) {
		o.AuditStore = store
	}
}

// loadConfig loads and validates environment configuration
func loadConfig() (*lambdaConfig, error) {
	cfg := &lambdaConfig{
		KmsKeyId:           os.Getenv(envKMSKeyID),
		JMESPathExpression: os.Getenv(envJMESPathExpression),
		DynamoDBTableName:  os.Getenv(envDynamoDBTable),
	}

	// Validate required fields
	if cfg.KmsKeyId == "" {
		return nil, fmt.Errorf("missing required env var: %s", envKMSKeyID)
	}
	if cfg.JMESPathExpression == "" {
		return nil, fmt.Errorf("missing required env var: %s", envJMESPathExpression)
	}
	if cfg.DynamoDBTableName == "" {
		return nil, fmt.Errorf("missing required env var: %s", envDynamoDBTable)
	}

	return cfg, nil
}

// loadDefaultOptions loads all default dependencies from environment and AWS
func loadDefaultOptions(ctx context.Context) (*InitOptions, error) {
	// Load and validate configuration
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	// Create context with timeout for AWS operations
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(initCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create KMS client
	kmcClient := kms.NewFromConfig(awsCfg)

	// Create SSH CA Signer from KMS-backed key
	caCertSigner, err := signer.NewSSHCertSigner(initCtx, signer.NewAWSKMSClient(kmcClient), cfg.KmsKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS SSH CA Signer: %w", err)
	}

	// Create principal mapper from JMESPath expression
	principalMapper, err := principals.NewJMESPathPrincipalMapper(cfg.JMESPathExpression)
	if err != nil {
		return nil, fmt.Errorf("failed to create principal mapper: %w", err)
	}

	// Initialize DynamoDB audit store
	auditStore, err := audit.NewDynamoDbAuditStore(cfg.DynamoDBTableName)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit store: %w", err)
	}

	return &InitOptions{
		SSHCertificateSigner: caCertSigner,
		PrincipalMapper:      principalMapper,
		AuditStore:           auditStore,
	}, nil
}

// initialize sets up all dependencies and returns the API Gateway handler
// It supports functional options for dependency injection in tests
func initialize(ctx context.Context, opts ...InitOption) (*APIGatewayHandler, error) {
	var options *InitOptions

	// If no custom options provided, load default options
	if len(opts) == 0 {
		defaultOpts, err := loadDefaultOptions(ctx)
		if err != nil {
			return nil, err
		}
		options = defaultOpts
	} else {
		options = &InitOptions{}
		for _, opt := range opts {
			opt(options)
		}
	}

	// Create signer handler with injected dependencies
	signerHandler := handler.NewSignerHandler(options.SSHCertificateSigner, options.PrincipalMapper, options.AuditStore)

	// Create API Gateway handler
	apigwHandler := NewAPIGatewayHandler(signerHandler)

	return apigwHandler, nil
}
