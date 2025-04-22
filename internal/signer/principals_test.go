package signer_test

import (
	"testing"

	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
)

func TestJMESPrincipalMapper(t *testing.T) {
	// Create a new JMESPathPrincipalMapper
	mapper := &signer.JMESPathPrincipalMapper{
		Expressions: []string{"sub", "email", "groups[*]"},
	}

	expectedPrincipals := []string{"user1", "test@test.com", "group1", "group2"}
	principals, err := mapper.Map(map[string]interface{}{
		"sub":    "user1",
		"email":  "test@test.com",
		"groups": []string{"group1", "group2"},
	})

	assert.NoError(t, err)
	assert.Equal(t, expectedPrincipals, principals)
}
