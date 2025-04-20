package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/sebastian-mora/aegis/internal/signer"
	"golang.org/x/crypto/ssh"
)

// Claims struct for the JWT payload
type Claims struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

// LambdaDeps includes only the Signer now
type LambdaDeps struct {
	Signer signer.Signer
}

func extractClaimsFromToken(token string) (*Claims, error) {
	// Split the token into three parts (Header, Payload, Signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Extract the payload segment (the second part of the JWT)
	payloadSegment := parts[1]

	// Decode the base64-encoded payload
	decoded, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, err
	}

	// Unmarshal the decoded payload into the Claims struct
	var claims Claims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}

	// Return the populated Claims struct
	return &claims, nil
}

// NewHandler creates a new Lambda handler function
func NewHandler(deps LambdaDeps) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

		fmt.Println("Starting Aegis Signer Lambda function...from HANDLER")
		const certificateExpiration = 24 * time.Hour

		fmt.Printf("Received body: %s\n", event.Body)

		authHeader := event.Headers["authorization"]
		if authHeader == "" {
			return events.APIGatewayV2HTTPResponse{
				StatusCode: 401,
				Body:       "missing authorization header",
			}, nil
		}

		// Force the certificate type to be UserCert
		var certificateType = ssh.UserCert

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := extractClaimsFromToken(token)
		if err != nil || claims.Email == "" {
			log.Printf("failed to extract email from token: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid token or missing email claim"}, nil
		}

		// Parse the public key from the request body
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
		if err != nil {
			log.Printf("failed to parse submitted public key: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid public key"}, nil
		}

		// Sign the certificate using the Signer
		userSSHCert, err := deps.Signer.Sign(uint32(certificateType), pubKey, []string{claims.Email}, certificateExpiration)
		if err != nil {
			log.Printf("failed to sign certificate: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 500, Body: "failed to sign certificate"}, nil
		}

		// Return the SSH certificate in response
		certString := string(ssh.MarshalAuthorizedKey(userSSHCert))
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

	fmt.Println("Starting Aegis Signer Lambda function...from MAIN")
	// Create a new AWS session
	sess, err := session.NewSession()
	if err != nil {
		log.Printf("failed to create AWS session: %v", err)
		return
	}

	secret_name := os.Getenv("USER_CA_KEY_NAME")

	// Load the certificate signer from AWS Secrets Manager
	caCertSigner, err := signer.NewAWSSMSource(secret_name, sess).Load()
	if err != nil {
		log.Printf("failed to load cert signer: %v", err)
		return
	}

	// Initialize the SSH signer
	sshSigner := &signer.SSHCASigner{CAPrivateKey: caCertSigner}

	// Inject dependencies into LambdaDeps
	deps := LambdaDeps{
		Signer: sshSigner,
	}

	// Initialize the handler with injected dependencies
	handler := NewHandler(deps)

	// Start the Lambda function with the handler
	lambda.Start(handler)
}
