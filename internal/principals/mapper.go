package principals

// PrincipalMapper defines the interface for mapping claims to principals.
type PrincipalMapper interface {
	Map(claims interface{}) ([]string, error)
}
