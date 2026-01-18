package handler_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/sebastian-mora/aegis/internal/handler"
)

type MockKMSClient struct{}

func (m *MockKMSClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	// Return a mock public key
	mockPubKey := []byte("ssh-rsa test123")
	return &kms.GetPublicKeyOutput{
		PublicKey: mockPubKey,
		KeyId:     input.KeyId,
		KeySpec:   types.KeySpecRsa2048,
	}, nil
}

func (m *MockKMSClient) Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, nil
}

func Test_PublicKey(t *testing.T) {
	// Create mock KMS client
	mockKMS := &MockKMSClient{}
	kmsKeyId := "mock-key-id"

	// Create KMSKeyHandler with mock client
	keyHandler := handler.NewKmsKeyHandler(mockKMS, kmsKeyId)

	// Call PublicKey method
	pubKey, err := keyHandler.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedPubKey := "ssh-rsa test123"
	if pubKey != expectedPubKey {
		t.Errorf("expected public key %s, got %s", expectedPubKey, pubKey)
	}
}
