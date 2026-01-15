package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/sebastian-mora/aegis/internal/audit"
	"github.com/sebastian-mora/aegis/internal/handler"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

// Environment variable names
const (
	envSecretName         = "USER_CA_KEY_NAME"
	envJMESPathExpression = "JSME_PATH_EXPRESSION"
	envDynamoDBTable      = "DYNAMO_DB_TABLE"
)

// lambdaConfig holds configuration loaded from environment
type lambdaConfig struct {
	SecretName         string
	JMESPathExpression string
	DynamoDBTableName  string
}

// InitOptions holds optional dependencies for initialization
type InitOptions struct {
	CACertSigner    ssh.Signer
	PrincipalMapper signer.PrincipalMapper
	AuditStore      audit.AuditWriter
}

type InitOption func(*InitOptions)

func WithCACertSigner(signer ssh.Signer) InitOption {
	return func(o *InitOptions) {
		o.CACertSigner = signer
	}
}

func WithPrincipalMapper(mapper signer.PrincipalMapper) InitOption {
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
		SecretName:         os.Getenv(envSecretName),
		JMESPathExpression: os.Getenv(envJMESPathExpression),
		DynamoDBTableName:  os.Getenv(envDynamoDBTable),
	}

	// Validate required fields
	if cfg.SecretName == "" {
		return nil, fmt.Errorf("missing required env var: %s", envSecretName)
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

	// Load CA certificate from Secrets Manager
	caCert, err := GetSecretFromSecretsManager(initCtx, awsCfg, cfg.SecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Parse SSH private key
	caCertSigner, err := ssh.ParsePrivateKey([]byte(caCert))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	// Create principal mapper from JMESPath expression
	principalMapper, err := signer.NewJMESPathPrincipalMapper(cfg.JMESPathExpression)
	if err != nil {
		return nil, fmt.Errorf("failed to create principal mapper: %w", err)
	}

	// Initialize DynamoDB audit store
	auditStore, err := audit.NewDynamoDbAuditStore(cfg.DynamoDBTableName)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit store: %w", err)
	}

	return &InitOptions{
		CACertSigner:    caCertSigner,
		PrincipalMapper: principalMapper,
		AuditStore:      auditStore,
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

	// Initialize SSH signer
	sshSigner := signer.NewSSHCASigner(options.CACertSigner)

	// Create signer handler with injected dependencies
	signerHandler := handler.NewSignerHandler(sshSigner, options.PrincipalMapper, options.AuditStore)

	// Create API Gateway handler
	apigwHandler := NewAPIGatewayHandler(signerHandler)

	return apigwHandler, nil
}
