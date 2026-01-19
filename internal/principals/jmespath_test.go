package principals_test

import (
	"testing"

	"github.com/sebastian-mora/aegis/internal/principals"
	"github.com/stretchr/testify/assert"
)

func TestJMESPrincipalMapper(t *testing.T) {

	t.Run("Test with valid JMESPath expression", func(t *testing.T) {

		// Create a new JMESPathPrincipalMapper
		mapper, err := principals.NewJMESPathPrincipalMapper("sub")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)

		expectedPrincipals := []string{"user1"}
		prncpls, err := mapper.Map(map[string]interface{}{
			"sub":    "user1",
			"email":  "test@test.com",
			"groups": []string{"group1", "group2"},
		})

		assert.NoError(t, err)
		assert.Equal(t, expectedPrincipals, prncpls)
	})

	t.Run("Test with expression that returns multiple principals", func(t *testing.T) {
		mapper, err := principals.NewJMESPathPrincipalMapper("groups[*]")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)
		expectedPrincipals := []string{"group1", "group2"}
		prncpls, err := mapper.Map(map[string]interface{}{
			"sub":    "user1",
			"email":  "test@test.com",
			"groups": []string{"group1", "group2"},
		})
		assert.NoError(t, err)
		assert.Equal(t, expectedPrincipals, prncpls)
	})

	t.Run("Test with expression concats muiti single attrs", func(t *testing.T) {
		mapper, err := principals.NewJMESPathPrincipalMapper("[sub, email]")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)
		expectedPrincipals := []string{"user1", "test@test.com"}
		prncpls, err := mapper.Map(map[string]interface{}{
			"sub":    "user1",
			"email":  "test@test.com",
			"groups": []string{"group1", "group2"},
		})
		assert.NoError(t, err)
		assert.ElementsMatch(t, expectedPrincipals, prncpls)
	})

	t.Run("Test with empty JMESPath expression", func(t *testing.T) {
		// Create a new JMESPathPrincipalMapper with an empty expression
		mapper, err := principals.NewJMESPathPrincipalMapper("")
		assert.Error(t, err)
		assert.Nil(t, mapper)
	})

	t.Run("Test with JMESPath expression that matches nothing", func(t *testing.T) {
		mapper, err := principals.NewJMESPathPrincipalMapper("no_match")
		assert.NoError(t, err)

		prncpls, err := mapper.Map(map[string]interface{}{
			"sub": "user1",
		})

		assert.Error(t, err, "expected error due to no match")
		assert.Nil(t, prncpls, "no principals should be returned")
	})

	t.Run("Test invalid JMESPath expression syntax", func(t *testing.T) {
		// Create a new JMESPathPrincipalMapper with an invalid expression
		mapper, err := principals.NewJMESPathPrincipalMapper("[test)")
		assert.Error(t, err)
		assert.Nil(t, mapper)

	})

	t.Run("Test nil claim data", func(t *testing.T) {
		mapper, err := principals.NewJMESPathPrincipalMapper("sub")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)

		prncpls, err := mapper.Map(nil)

		assert.Error(t, err, "expected error due to nil claim data")
		assert.Nil(t, prncpls, "no principals should be returned")
	})

	t.Run("Test with JMESPath expression that returns non-string/non-list", func(t *testing.T) {
		mapper, err := principals.NewJMESPathPrincipalMapper("length(sub)")
		assert.NoError(t, err)

		prncpls, err := mapper.Map(map[string]interface{}{
			"sub": "user1",
		})

		assert.Error(t, err, "expected error due to non-string/non-list result")
		assert.Nil(t, prncpls, "no principals should be returned")
	})

	t.Run("Test deduplication", func(t *testing.T) {
		mapper, err := principals.NewJMESPathPrincipalMapper("groups[*]")
		assert.NoError(t, err)
		assert.NotNil(t, mapper)
		expectedPrincipals := []string{"group1", "group2"}
		prncpls, err := mapper.Map(map[string]interface{}{
			"sub":    "user1",
			"email":  "test@test.com",
			"groups": []string{"group1", "group2", "group1"},
		})
		assert.NoError(t, err)
		assert.ElementsMatch(t, expectedPrincipals, prncpls)
	})
}
