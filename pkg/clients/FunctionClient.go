package clients

type FunctionClient interface {
	GetFuncCode(funcIdentifier string) (string, error)
}
