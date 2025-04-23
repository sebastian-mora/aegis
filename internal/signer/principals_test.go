package signer_test

import (
	"testing"

	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
)

func TestJMESPrincipalMapper(t *testing.T) {
	// Create a new JMESPathPrincipalMapper
	mapper, err := signer.NewJMESPathPrincipalMapper("sub")
	assert.NoError(t, err)
	assert.NotNil(t, mapper)

	expectedPrincipals := []string{"user1"}
	principals, err := mapper.Map(map[string]interface{}{
		"sub":    "user1",
		"email":  "test@test.com",
		"groups": []string{"group1", "group2"},
	})

}
func TestJMESPrincipalMapperFlattenList(t *testing.T) {
	// Create a new JMESPathPrincipalMapper
	mapper, err := signer.NewJMESPathPrincipalMapper("unix_groups[*]")
	assert.NoError(t, err)
	assert.NotNil(t, mapper)

	expectedPrincipals := []string{"group1", "group2"}
	principals, err := mapper.Map(map[string]interface{}{
		"sub":         "user1",
		"email":       "test@test.com",
		"unix_groups": []string{"group1", "group2"},
	})

	assert.NoError(t, err)
	assert.Equal(t, expectedPrincipals, principals)
}
