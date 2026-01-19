package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func GetSecretFromSecretsManager(ctx context.Context, cfg aws.Config, secretName string) (string, error) {
	svc := secretsmanager.NewFromConfig(cfg)

	out, err := svc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to retrieve secret %s: %w", secretName, err)
	}

	if out.SecretString == nil {
		return "", fmt.Errorf("secret %s has no SecretString", secretName)
	}

	return *out.SecretString, nil
}
