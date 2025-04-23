package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
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

func TestGenerateID(t *testing.T) {
	sub := "ruse"
	signedAt := time.Now().UTC()
	timestamp := signedAt.UTC().Format(time.RFC3339)

	expected := sub + "-" + timestamp

	assert.Equal(t, expected, GenerateID(signedAt, sub))

}

func TestWriteAuditEvent(t *testing.T) {

	signedAt := time.Now().UTC()

	mockClient := &mockDynamoClient{
		PutItemFunc: func(ctx context.Context, input *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {

			assert.NotNil(t, input)
			assert.Equal(t, "audit-table", *input.TableName)

			// Check the fields in the item map
			assert.Contains(t, input.Item, "ID")
			assert.Contains(t, input.Item, "SignedAt")
			assert.Equal(t, &types.AttributeValueMemberS{Value: "test-user"}, input.Item["Sub"])

			// Assert the id is generated correctly
			assert.Equal(t, input.Item["ID"], fmt.Sprintf("%s-%s", signedAt, input.Item["Sub"]))

			// Return mock output
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	// Create the DynamoAuditStore with the mock client
	store := &DynamoAuditStore{
		Client:    mockClient,
		TableName: "audit-table",
	}

	// Define an audit event for testing
	event := KeySignEvent{
		SignedAt:    signedAt,
		PublicKey:   "ssh-ed25519 AAA...",
		Certificate: "ssh-ed25519-cert AAA...",
		Principals:  []string{"alice", "bob"},
		SourceIp:    "192.168.1.1",
		UserAgent:   "curl/7.79.1",
		Sub:         "test-user",
		Aud:         "service-x",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}

	err := store.Write(event)
	assert.NoError(t, err)
}
