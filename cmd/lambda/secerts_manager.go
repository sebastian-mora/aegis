package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func GetSecretFromSecretsManager(sess *session.Session, secretName string) (string, error) {
	svc := secretsmanager.New(sess)
	out, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to retrieve secret %s: %w", secretName, err)
	}

	if out.SecretString == nil {
		return "", fmt.Errorf("secret %s has no SecretString", secretName)
	}

	return string(*out.SecretString), nil
}
