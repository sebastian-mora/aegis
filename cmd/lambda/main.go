package main

import (
	"context"
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

// LambdaDeps includes only the Signer now
type LambdaDeps struct {
	Signer          signer.Signer
	PrincipalMapper signer.PrincipalMapper
}

// NewHandler creates a new Lambda handler function
func NewHandler(deps LambdaDeps) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

		fmt.Println("Starting Aegis Signer Lambda function...from HANDLER")
		const certificateExpiration = 24 * time.Hour

		// Map ssh certificate principals from the JWT token
		principals, err := deps.PrincipalMapper.Map(event.Headers["Authorization"])
		if err != nil {
			log.Printf("failed to map principals from token: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "principal mapping failed"}, nil
		}

		// Parse the public key from the request body
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
		if err != nil {
			log.Printf("failed to parse submitted public key: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 400, Body: "invalid public key"}, nil
		}

		// Sign the certificate using the Signer
		userSSHCert, err := deps.Signer.Sign(uint32(ssh.UserCert), pubKey, principals, certificateExpiration)
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

	// Load JSME Expressions from environment variable
	jmesPathExpressions := os.Getenv("JSME_PATH_EXPRESSIONS")
	if jmesPathExpressions == "" {
		log.Printf("failed to load JMESPath expressions from environment variable")
		return
	}

	// Split the JMESPath expressions into a slice
	expressions := []string{}
	for _, expr := range strings.Split(jmesPathExpressions, ",") {
		expressions = append(expressions, strings.TrimSpace(expr))
	}

	// Create JSMEPathPrincipalMapper
	principalMapper := &signer.JMESPathPrincipalMapper{
		Expressions: expressions,
	}

	// // Initialize the SSH signer
	sshSigner := signer.NewSSHCASigner(caCertSigner)

	// Inject dependencies into LambdaDeps
	deps := LambdaDeps{
		Signer:          sshSigner,
		PrincipalMapper: principalMapper,
	}

	// Initialize the handler with injected dependencies
	handler := NewHandler(deps)

	// Start the Lambda function with the handler
	lambda.Start(handler)
}
