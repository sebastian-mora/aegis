package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

// LambdaDeps includes only the Signer now
type LambdaDeps struct {
	Signer          signer.Signer
	PrincipalMapper signer.PrincipalMapper
	AuditRepo       AuditWriter
}

// This custom parsing is required due to a bug in the lambda-events SDK
// Tracking issue:  https://github.com/aws/aws-lambda-go/issues/570
func ParseJWTClaims(tokenString string) (map[string]interface{}, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Convert to a map[string]interface{}
		return map[string]interface{}(claims), nil
	}

	return nil, fmt.Errorf("invalid token claims type")
}

func ParseTTL(ttl string) (time.Duration, error) {
	parsedTTL, err := time.ParseDuration(ttl)
	if err != nil {
		return 0, fmt.Errorf("failed to parse ttl: %w", err)
	}

	if parsedTTL <= 0 {
		return 0, fmt.Errorf("ttl must be greater than 0")
	}

	// set max TTL to 30 days
	// This is a measure to prevent long-lived certificates
	if parsedTTL > time.Duration(30*24*time.Hour) {
		return 0, fmt.Errorf("ttl is too long")
	}

	return parsedTTL, nil
}

// NewHandler creates a new Lambda handler function
func NewHandler(deps LambdaDeps) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

		slog.Info("Starting Aegis Signer Lambda function")
		var certificateExpiration = time.Duration(24 * time.Hour)

		// Parse the JWT token to get the Claims
		authHeader := event.Headers["authorization"] // Header keys may be lowercased by API Gateway
		if authHeader == "" {
			return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "Missing Authorization header"}, nil
		}

		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "Invalid Authorization format"}, nil
		}

		tokenStr := strings.TrimPrefix(authHeader, prefix)

		parsedTokenClaims, err := ParseJWTClaims(tokenStr)
		if err != nil {
			return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "Failed to parse jwt token"}, nil
		}

		// fetch audit requirements
		aud, audOk := parsedTokenClaims["aud"].(string)
		sub, subOk := parsedTokenClaims["sub"].(string)
		if !audOk || !subOk {
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "Missing or invalid 'aud' or 'sub' claim"}, nil
		}

		// Map the JWT claims to SSH principals
		principals, err := deps.PrincipalMapper.Map(parsedTokenClaims)
		if err != nil {
			slog.Info("No principals matched from token, no cert generated", "error", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 200, Body: "no principals matched on auth token"}, nil
		}

		// Parse the public key from the request body
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
		if err != nil {
			slog.Error("failed to parse submitted public key", "error", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid public key"}, nil
		}

		// Use the ttl from the query string if provided
		// otherwise use the default TTL
		if rawTTL := event.QueryStringParameters["ttl"]; rawTTL != "" {
			ttl, err := ParseTTL(rawTTL)
			if err != nil {
				slog.Error("failed to parse ttl", "error", err)
				return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: err.Error()}, nil
			}
			certificateExpiration = ttl
		}

		// Sign the certificate using the Signer
		userSSHCert, err := deps.Signer.Sign(uint32(ssh.UserCert), pubKey, principals, certificateExpiration)
		if err != nil {
			slog.Error("failed to sign certificate", "error", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "failed to sign certificate"}, nil
		}

		// Return the SSH certificate in response
		certString := string(ssh.MarshalAuthorizedKey(userSSHCert))

		// Write event to audit trail
		keySignEvent := KeySignEvent{
			SignedAt:    time.Now().UTC(),
			PublicKey:   string(ssh.MarshalAuthorizedKey(pubKey)),
			Certificate: certString,
			Principals:  principals,
			SourceIp:    event.RequestContext.HTTP.SourceIP,
			UserAgent:   event.RequestContext.HTTP.UserAgent,
			Sub:         sub,
			Aud:         aud,
			ExpiresAt:   time.Unix(int64(userSSHCert.ValidBefore), 0).UTC(),
		}

		if err := deps.AuditRepo.Write(keySignEvent); err != nil {
			slog.Error("Failed to write audit log", "error", err)
			slog.Info("Audit Event", "data", keySignEvent)
		}

		return events.APIGatewayV2HTTPResponse{
			StatusCode: 200,
			Body:       certString,
			Headers: map[string]string{
				"Content-Type": "text/plain",
			},
		}, nil
	}
}

func main() {

	// Load env vars

	secret_name := os.Getenv("USER_CA_KEY_NAME")
	jmesPathExpression := os.Getenv("JSME_PATH_EXPRESSION")
	dynamoDbTableName := os.Getenv("DYNAMO_DB_TABLE")

	// Create a new AWS session
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load AWS config: %v", err)
	}

	// Load the certificate signer from AWS Secrets Manager
	caCert, err := GetSecretFromSecretsManager(ctx, cfg, secret_name)
	if err != nil {
		slog.Error("failed to load cert signer", "error", err)
		return
	}

	// Create a new SSH signer from the private key
	caCertSigner, err := ssh.ParsePrivateKey([]byte(caCert))
	if err != nil {
		slog.Error("failed to parse private key", "error", err)
		return
	}

	// Load JSME Expressions from environment variable

	if jmesPathExpression == "" {
		slog.Error("failed to load JMESPath expressions from environment variable")
		return
	}

	// Check if any expressions were provided
	if len(jmesPathExpression) == 0 {
		slog.Error("no JMESPath expressions provided")
		return
	}

	// Create JSMEPathPrincipalMapper
	principalMapper, err := signer.NewJMESPathPrincipalMapper(jmesPathExpression)
	if err != nil {
		slog.Error("failed to create JMESPathPrincipalMapper", "error", err)
		return
	}

	// // Initialize the SSH signer
	sshSigner := signer.NewSSHCASigner(caCertSigner)

	// Init Audit Writer
	dynmoDbAuditStore, err := NewDynamoDbAuditStore(dynamoDbTableName)
	if err != nil {
		slog.Error("failed to create Dynamodb audit store", "error", err)
		return
	}

	// Inject dependencies into LambdaDeps
	deps := LambdaDeps{
		Signer:          sshSigner,
		PrincipalMapper: principalMapper,
		AuditRepo:       dynmoDbAuditStore,
	}

	// Initialize the handler with injected dependencies
	handler := NewHandler(deps)

	// Start the Lambda function with the handler
	lambda.Start(handler)
}
