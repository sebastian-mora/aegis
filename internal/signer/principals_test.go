package signer_test

import (
	"testing"

	"github.com/sebastian-mora/aegis/internal/signer"
	"github.com/stretchr/testify/assert"
)

func TestJMESPrincipalMapper(t *testing.T) {

	t.Run("Test with valid JMESPath expression", func(t *testing.T) {

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

		assert.NoError(t, err)
		assert.Equal(t, expectedPrincipals, principals)
	})

	t.Run("Test with expression that returns multiple principals", func(t *testing.T) {
		mapper, err := signer.NewJMESPathPrincipalMapper("groups[*]")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)
		expectedPrincipals := []string{"group1", "group2"}
		principals, err := mapper.Map(map[string]interface{}{
			"sub":    "user1",
			"email":  "test@test.com",
			"groups": []string{"group1", "group2"},
		})
		assert.NoError(t, err)
		assert.Equal(t, expectedPrincipals, principals)
	})

	t.Run("Test with expression concats muiti single attrs", func(t *testing.T) {
		mapper, err := signer.NewJMESPathPrincipalMapper("[sub, email]")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)
		expectedPrincipals := []string{"user1", "test@test.com"}
		principals, err := mapper.Map(map[string]interface{}{
			"sub":    "user1",
			"email":  "test@test.com",
			"groups": []string{"group1", "group2"},
		})
		assert.NoError(t, err)
		assert.Equal(t, expectedPrincipals, principals)
	})

	t.Run("Test with empty JMESPath expression", func(t *testing.T) {
		// Create a new JMESPathPrincipalMapper with an empty expression
		mapper, err := signer.NewJMESPathPrincipalMapper("")
		assert.Error(t, err)
		assert.Nil(t, mapper)
	})

	t.Run("Test with JMESPath expression that matches nothing", func(t *testing.T) {
		mapper, err := signer.NewJMESPathPrincipalMapper("no_match")
		assert.NoError(t, err)

		principals, err := mapper.Map(map[string]interface{}{
			"sub": "user1",
		})

		assert.Error(t, err, "expected error due to no match")
		assert.Nil(t, principals, "no principals should be returned")
	})

	t.Run("Test invalid JMESPath expression syntax", func(t *testing.T) {
		// Create a new JMESPathPrincipalMapper with an invalid expression
		mapper, err := signer.NewJMESPathPrincipalMapper("[test)")
		assert.Error(t, err)
		assert.Nil(t, mapper)

	})

}
