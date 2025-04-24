package main

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuditWriter interface {
	Write(event KeySignEvent) error
}

type KeySignEvent struct {
	ID          string    // Timestamp + SUB
	SignedAt    time.Time // Timestamp of the signing event
	PublicKey   string    // Original public key
	Certificate string    // Signed certificate
	Principals  []string  // List of SSH principals
	SourceIp    string    // IP address where the request came from
	UserAgent   string    // Optional: User agent of the requestor
	Sub         string    // Subject (user ID)
	Aud         string    // Audience (who this was issued for)
	ExpiresAt   int64     // Optional: for TTL
}

type DynamoClient interface {
	PutItem(ctx context.Context, input *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

type DynamoAuditStore struct {
	Client    DynamoClient
	TableName string
}

func NewDynamoDbAuditStore(tableName string) (*DynamoAuditStore, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	dbClient := dynamodb.NewFromConfig(cfg)

	return &DynamoAuditStore{
		Client:    dbClient,
		TableName: tableName,
	}, nil
}

func (store *DynamoAuditStore) Write(event KeySignEvent) error {

	item := map[string]types.AttributeValue{
		"SignedAt":    &types.AttributeValueMemberS{Value: event.SignedAt.Format(time.RFC3339)},
		"PublicKey":   &types.AttributeValueMemberS{Value: event.PublicKey},
		"Certificate": &types.AttributeValueMemberS{Value: event.Certificate},
		"SourceIp":    &types.AttributeValueMemberS{Value: event.SourceIp},
		"Sub":         &types.AttributeValueMemberS{Value: event.Sub},
		"Aud":         &types.AttributeValueMemberS{Value: event.Aud},
		"ExpiresAt":   &types.AttributeValueMemberS{Value: aws.ToString(aws.String(string(rune(event.ExpiresAt))))},
		"UserAgent":   &types.AttributeValueMemberS{Value: event.UserAgent},
	}

	if len(event.Principals) > 0 {
		principals := make([]types.AttributeValue, len(event.Principals))
		for i, p := range event.Principals {
			principals[i] = &types.AttributeValueMemberS{Value: p}
		}
		item["Principals"] = &types.AttributeValueMemberL{Value: principals}
	}

	_, err := store.Client.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: aws.String(store.TableName),
		Item:      item,
	})
	return err
}
