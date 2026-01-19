package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/sebastian-mora/aegis/internal/handler"
	"github.com/sebastian-mora/aegis/internal/logger"
)

// APIGatewayHandler handles API Gateway V2 HTTP requests and delegates to a Signer
type APIGatewayHandler struct {
	signer handler.Signer
}

// NewAPIGatewayHandler creates a new APIGatewayHandler with a Signer implementation
func NewAPIGatewayHandler(signer handler.Signer) *APIGatewayHandler {
	return &APIGatewayHandler{
		signer: signer,
	}
}

// Handle processes an API Gateway V2 HTTP request
func (h *APIGatewayHandler) Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

	// Add context about the Lambda invocation
	lambdaCtx, ok := lambdacontext.FromContext(ctx)
	if ok {
		ctx = context.WithValue(ctx, logger.AWSRequestIDKey, lambdaCtx.AwsRequestID)
		ctx = context.WithValue(ctx, logger.FunctionARNKey, lambdaCtx.InvokedFunctionArn)
	}

	// Add API Gateway request ID
	ctx = context.WithValue(ctx, logger.RequestIDKey, event.RequestContext.RequestID)
	ctx = context.WithValue(ctx, logger.SourceIPKey, event.RequestContext.HTTP.SourceIP)

	// Extract authorization token
	authHeader := event.Headers["authorization"]
	if authHeader == "" {
		return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "Missing Authorization header"}, nil
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return events.APIGatewayV2HTTPResponse{StatusCode: 401, Body: "Invalid Authorization format"}, nil
	}

	tokenStr := strings.TrimPrefix(authHeader, prefix)

	// Extract TTL from query parameters
	ttl := event.QueryStringParameters["ttl"]

	// Create request object for the signer
	req := &handler.SigningRequest{
		Token:     tokenStr,
		PublicKey: event.Body,
		TTL:       ttl,
		SourceIP:  event.RequestContext.HTTP.SourceIP,
		UserAgent: event.RequestContext.HTTP.UserAgent,
	}

	// Call the signer
	resp, err := h.signer.SignRequest(ctx, req)
	if err != nil {
		slog.Error("signing request failed", "error", err)

		// Map errors to appropriate HTTP status codes based on error type
		statusCode := 500
		body := "Internal server error"

		if errors.Is(err, handler.ErrUnauthorized) {
			statusCode = 401
			body = "Unauthorized: invalid or missing authentication"
		} else if errors.Is(err, handler.ErrInvalidRequest) {
			statusCode = 400
			body = "Bad request: invalid input parameters"
		}
		// ErrInternalServer defaults to 500 with generic message

		return events.APIGatewayV2HTTPResponse{
			StatusCode: statusCode,
			Body:       body,
		}, nil
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       resp.Certificate,
		Headers: map[string]string{
			"Content-Type": "text/plain",
		},
	}, nil
}
