package signer_test

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type MockKMSClient struct {
	SignFunc         func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKeyFunc func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

func NewMockKMSClient() *MockKMSClient {
	return &MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{}, nil
		},
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{}, nil
		},
	}
}

func (m *MockKMSClient) WithSign(fn func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)) *MockKMSClient {
	m.SignFunc = fn
	return m
}

func (m *MockKMSClient) WithGetPublicKey(fn func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)) *MockKMSClient {
	m.GetPublicKeyFunc = fn
	return m
}

func (m *MockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.SignFunc == nil {
		return &kms.SignOutput{}, nil
	}
	return m.SignFunc(ctx, params, optFns...)
}

func (m *MockKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if m.GetPublicKeyFunc == nil {
		return &kms.GetPublicKeyOutput{}, nil
	}
	return m.GetPublicKeyFunc(ctx, params, optFns...)
}
