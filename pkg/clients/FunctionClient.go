package clients

type FunctionClient interface {
	GetFuncCode(funcIdentifier string) (string, error)
	TagFunction(funcIdentifier string, tag string, tagValue string) (string, error)
}
