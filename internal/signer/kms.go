package signer

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type AwsKMSApi interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

type AWSKMSClient struct {
	client *kms.Client
}

func NewAWSKMSClient(client *kms.Client) *AWSKMSClient {
	return &AWSKMSClient{client: client}
}
func (a *AWSKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return a.client.Sign(ctx, params, optFns...)
}
func (a *AWSKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return a.client.GetPublicKey(ctx, params, optFns...)
}
