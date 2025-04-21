package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

func extractClaimsFromRequest(event events.APIGatewayV2HTTPRequest) (*Claims, error) {
	claimsMap := event.RequestContext.Authorizer.JWT.Claims

	email, ok := claimsMap["email"]
	if !ok {
		return nil, fmt.Errorf("email claim missing")
	}

	username, ok := claimsMap["username"]
	if !ok {
		return nil, fmt.Errorf("username claim missing")
	}

	return &Claims{
		Email:    email,
		Username: username,
	}, nil
}

// NewHandler creates a new Lambda handler function
func NewHandler(deps LambdaDeps) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

		fmt.Println("Starting Aegis Signer Lambda function...from HANDLER")
		const certificateExpiration = 24 * time.Hour

		fmt.Printf("Received body: %s\n", event.Body)

		claims, err := extractClaimsFromRequest(event)
		if err != nil || claims.Email == "" {
			log.Printf("failed to extract email from claims: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid token or missing email claim"}, nil
		}

		// Parse the public key from the request body
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
		if err != nil {
			log.Printf("failed to parse submitted public key: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid public key"}, nil
		}

		// Sign the certificate using the Signer
		userSSHCert, err := deps.Signer.Sign(uint32(ssh.UserCert), pubKey, []string{claims.Email}, certificateExpiration)
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
	caCert, err := GetSecretFromSecretsManager(sess, secret_name)
	if err != nil {
		log.Printf("failed to load cert signer: %v", err)
		return
	}

	// Create a new SSH signer from the private key
	caCertSigner, err := ssh.ParsePrivateKey([]byte(caCert))
	if err != nil {
		log.Printf("failed to parse private key: %v", err)
		return
	}

	// // Initialize the SSH signer
	sshSigner := signer.NewSSHCASigner(caCertSigner)

	// Inject dependencies into LambdaDeps
	deps := LambdaDeps{
		Signer: sshSigner,
	}

	// Initialize the handler with injected dependencies
	handler := NewHandler(deps)

	// Start the Lambda function with the handler
	lambda.Start(handler)
}
