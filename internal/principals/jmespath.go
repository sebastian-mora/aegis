package principals

import (
	"fmt"
	"slices"

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

	if result == nil {
		return nil, fmt.Errorf("no matches found for expression")
	}

	switch v := result.(type) {

	case string:
		return []string{v}, nil

	case []interface{}:
		var principals []string

		// Attempt to convert each item to string
		for _, item := range v {
			if s, ok := item.(string); ok {
				principals = append(principals, s)
			} else {
				return nil, fmt.Errorf("expression result contains non-string item")
			}
		}

		// Sort and remove duplicates from principals
		slices.Sort(principals)
		return slices.Compact(principals), nil

	default:
		return nil, fmt.Errorf("expression result is neither a string nor a list of strings")
	}
}
