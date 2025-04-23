package signer

import (
	"fmt"

	"github.com/jmespath/go-jmespath"
)

type PrincipalMapper interface {
	Map(claims map[string]interface{}) ([]string, error)
}

type JMESPathPrincipalMapper struct {
	JMESPath *jmespath.JMESPath
}

func NewJMESPathPrincipalMapper(expression string) (*JMESPathPrincipalMapper, error) {

	// Check if the expression is empty
	if expression == "" {
		return nil, fmt.Errorf("expression cannot be empty")
	}

	path, err := jmespath.Compile(expression)
	if err != nil {
		return nil, fmt.Errorf("invalid JMESPath expression: %w", err)
	}

	return &JMESPathPrincipalMapper{
		JMESPath: path,
	}, nil
}

func (m *JMESPathPrincipalMapper) Map(claims map[string]interface{}) ([]string, error) {

	// Check if claims is nil
	if claims == nil {
		return nil, fmt.Errorf("claims cannot be nil")
	}

	seen := make(map[string]struct{})
	var principals []string

	result, err := m.JMESPath.Search(claims)
	if err != nil {
		return nil, err
	}

	switch v := result.(type) {
	case string:
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			principals = append(principals, v)
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if _, exists := seen[s]; !exists {
					seen[s] = struct{}{}
					principals = append(principals, s)
				}
			}
		}
	}

	return principals, nil
}
