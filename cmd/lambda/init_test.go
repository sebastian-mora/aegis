package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name      string
		setupEnv  map[string]string
		expectErr string
		expectCfg *lambdaConfig
	}{
		{
			name: "valid config",
			setupEnv: map[string]string{
				envKMSKeyID:           "test-key-id",
				envJMESPathExpression: "email",
				envDynamoDBTable:      "test-table",
			},
			expectCfg: &lambdaConfig{
				KmsKeyId:           "test-key-id",
				JMESPathExpression: "email",
				DynamoDBTableName:  "test-table",
			},
		},
		{
			name: "missing secret name",
			setupEnv: map[string]string{
				envJMESPathExpression: "email",
				envDynamoDBTable:      "test-table",
			},
			expectErr: "missing required env var: KMS_KEY_ID",
		},
		{
			name: "missing JMESPath expression",
			setupEnv: map[string]string{
				envKMSKeyID:      "test-key-id",
				envDynamoDBTable: "test-table",
			},
			expectErr: "missing required env var: JSME_PATH_EXPRESSION",
		},
		{
			name: "missing DynamoDB table",
			setupEnv: map[string]string{
				envKMSKeyID:           "test-key-id",
				envJMESPathExpression: "email",
			},
			expectErr: "missing required env var: DYNAMO_DB_TABLE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing env vars
			os.Unsetenv(envKMSKeyID)
			os.Unsetenv(envJMESPathExpression)
			os.Unsetenv(envDynamoDBTable)

			// Set test env vars
			for k, v := range tt.setupEnv {
				os.Setenv(k, v)
			}
			defer func() {
				os.Unsetenv(envKMSKeyID)
				os.Unsetenv(envJMESPathExpression)
				os.Unsetenv(envDynamoDBTable)
			}()

			cfg, err := loadConfig()

			if tt.expectErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectCfg, cfg)
			}
		})
	}
}
