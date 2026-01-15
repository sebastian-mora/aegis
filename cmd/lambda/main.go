package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	// Initialize all dependencies
	handler, err := initialize(context.Background())
	if err != nil {
		slog.Error("initialization failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Lambda handler initialized successfully")

	// Start Lambda runtime
	lambda.Start(handler.Handle)
}
