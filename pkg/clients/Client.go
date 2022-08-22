package clients

type Client interface {
	GetFuncCode(funcIdentifier string) (string, error)
	Upload(signature string, identity string) error
	Download(identity string) (string, error)
}
