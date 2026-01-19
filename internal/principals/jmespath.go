package principals

import (
	"fmt"

	"github.com/jmespath/go-jmespath"
)

type JMESPathPrincipalMapper struct {
	Exp *jmespath.JMESPath
}

func NewJMESPathPrincipalMapper(expression string) (*JMESPathPrincipalMapper, error) {
	if expression == "" {
		return nil, fmt.Errorf("expression cannot be empty")
	}

	exp, err := jmespath.Compile(expression)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression: %v", err)
	}

	return &JMESPathPrincipalMapper{
		Exp: exp,
	}, nil
}

func (m *JMESPathPrincipalMapper) Map(claims interface{}) ([]string, error) {
	if claims == nil {
		return nil, fmt.Errorf("claims cannot be nil")
	}

	result, err := m.Exp.Search(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate expression: %v", err)
	}

	// If there are no matches, return an empty list
	if result == nil {
		return nil, fmt.Errorf("no matches found for expression")
	}

	seen := make(map[string]struct{})
	var principals []string

	switch v := result.(type) {
	case string:
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			principals = append(principals, v)
		}
	case []interface{}:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if _, exists := seen[s]; !exists {
				seen[s] = struct{}{}
				principals = append(principals, s)
			}
		}
	default:
		return nil, fmt.Errorf("expression result is neither a string nor a list of strings")
	}

	return principals, nil
}
