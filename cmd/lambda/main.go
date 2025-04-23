package main

import (
	"context"
	"encoding/json"
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

// LambdaDeps includes only the Signer now
type LambdaDeps struct {
	Signer          signer.Signer
	PrincipalMapper signer.PrincipalMapper
}

func convertClaimsToInterfaceMap(claims map[string]string) (map[string]interface{}, error) {
	interfaceClaims := make(map[string]interface{})

	for key, value := range claims {
		var parsedValue interface{}

		// Try unmarshaling the string value into a generic interface{}
		if err := json.Unmarshal([]byte(value), &parsedValue); err == nil {
			interfaceClaims[key] = parsedValue
		} else {
			// If unmarshaling fails, treat the value as a plain string
			interfaceClaims[key] = value
		}
	}

	return interfaceClaims, nil
}

// NewHandler creates a new Lambda handler function
func NewHandler(deps LambdaDeps) func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

		fmt.Println("Starting Aegis Signer Lambda function...from HANDLER")
		const certificateExpiration = 24 * time.Hour

		// Massage the JWT claims to map[string]interface{}
		// This is necessary because the AWS Lambda Go SDK uses a map[string]string
		// for JWT claims, but we need to convert it to map[string]interface{}
		// to work with the PrincipalMapper
		stringClaims := event.RequestContext.Authorizer.JWT.Claims
		interfaceClaims, err := convertClaimsToInterfaceMap(stringClaims)
		if err != nil {
			log.Fatalf("Error converting claims: %v", err)
		}

		// Map the JWT claims to SSH principals
		principals, err := deps.PrincipalMapper.Map(interfaceClaims)
		if err != nil {
			log.Printf("failed to map principals from token: %v", err)
			return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "principal mapping failed"}, nil
		}

		if len(principals) == 0 {
			log.Printf("no principals found in token")
			return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "no principals found"}, nil
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
	jmesPathExpression := os.Getenv("JSME_PATH_EXPRESSION")
	if jmesPathExpression == "" {
		log.Printf("failed to load JMESPath expression from environment variable")
		return
	}

	// Create JSMEPathPrincipalMapper
	principalMapper, err := signer.NewJMESPathPrincipalMapper(jmesPathExpression)
	if err != nil {
		log.Printf("failed to create JMESPathPrincipalMapper: %v", err)
		return
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
