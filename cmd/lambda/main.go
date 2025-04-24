package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

// LambdaDeps includes only the Signer now
type LambdaDeps struct {
	Signer          signer.Signer
	PrincipalMapper signer.PrincipalMapper
	AuditRepo       AuditWriter
}

func convertClaims(stringClaims map[string]string) map[string]interface{} {
	interfaceClaims := make(map[string]interface{}, len(stringClaims))
	for k, v := range stringClaims {
		// Try to parse JSON value if possible
		var parsed interface{}
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			interfaceClaims[k] = parsed
		} else {
			// Just a string, store as-is
			interfaceClaims[k] = v
		}
	}
	return interfaceClaims
}

// NewHandler creates a new Lambda handler function
func NewHandler(deps LambdaDeps) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

		slog.Info("Starting Aegis Signer Lambda function")
		const certificateExpiration = 24 * time.Hour

		// Massage the JWT claims to map[string]interface{}
		// This is necessary because the AWS Lambda Go SDK uses a map[string]string
		// for JWT claims, but we need to convert it to map[string]interface{}
		// to work with the PrincipalMapper
		stringClaims := event.RequestContext.Authorizer.JWT.Claims
		interfaceClaims := convertClaims(stringClaims)

		// Map the JWT claims to SSH principals
		principals, err := deps.PrincipalMapper.Map(interfaceClaims)
		if err != nil {
			slog.Error("failed to map principals from token", "error", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "principal mapping failed"}, nil
		}

		// Parse the public key from the request body
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
		if err != nil {
			slog.Error("failed to parse submitted public key", "error", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid public key"}, nil
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
			Sub:         event.RequestContext.Authorizer.JWT.Claims["sub"],
			Aud:         event.RequestContext.Authorizer.JWT.Claims["aud"],
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
	sess, err := session.NewSession()
	if err != nil {
		slog.Error("failed to create AWS session", "error", err)
		return
	}

	// Load the certificate signer from AWS Secrets Manager
	caCert, err := GetSecretFromSecretsManager(sess, secret_name)
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
