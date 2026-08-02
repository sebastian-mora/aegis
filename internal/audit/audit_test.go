package audit

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock for the DynamoDB client interface
type mockDynamoClient struct {
	PutItemFunc func(ctx context.Context, input *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

func (m *mockDynamoClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.PutItemFunc != nil {
		return m.PutItemFunc(ctx, input, optFns...)
	}
	return &dynamodb.PutItemOutput{}, nil
}

func TestWriteAuditEvent(t *testing.T) {
	signedAt := time.Now()

	var actualInput *dynamodb.PutItemInput

	mockClient := &mockDynamoClient{
		PutItemFunc: func(ctx context.Context, input *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			actualInput = input
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	store := &DynamoAuditStore{
		Client:    mockClient,
		TableName: "audit-table",
	}

	event := KeySignEvent{
		SignedAt:               signedAt,
		PublicKey:              "ssh-ed25519 AAA...",
		PublicKeyFingerprint:   "SHA256:pubkeyfingerprint",
		CertificateKeyId:       "cert-12345",
		CAPublicKeyFingerprint: "SHA256:cafingerprint",
		Principals:             []string{"alice", "bob"},
		SourceIp:               "192.168.1.1",
		UserAgent:              "curl/7.79.1",
		Sub:                    "test-user",
		Aud:                    "service-x",
		Iss:                    "https://idp.example.com",
		ExpiresAt:              time.Now().Add(time.Hour * 12),
	}

	err := store.Write(event)
	assert.NoError(t, err)

	require.NotNil(t, actualInput)
	assert.Equal(t, "audit-table", *actualInput.TableName)
	assert.Contains(t, actualInput.Item, "SignedAt")

	// Check some key fields
	assert.Equal(t, &types.AttributeValueMemberS{Value: "test-user"}, actualInput.Item["Sub"])
	assert.Equal(t, &types.AttributeValueMemberS{Value: "ssh-ed25519 AAA..."}, actualInput.Item["PublicKey"])
	assert.Equal(t, &types.AttributeValueMemberS{Value: "SHA256:pubkeyfingerprint"}, actualInput.Item["PublicKeyFingerprint"])
	assert.Equal(t, &types.AttributeValueMemberS{Value: "SHA256:cafingerprint"}, actualInput.Item["CAPublicKeyFingerprint"])
	assert.Equal(t, &types.AttributeValueMemberS{Value: "cert-12345"}, actualInput.Item["CertificateKeyId"])
	assert.Equal(t, &types.AttributeValueMemberS{Value: "https://idp.example.com"}, actualInput.Item["Iss"])
}
