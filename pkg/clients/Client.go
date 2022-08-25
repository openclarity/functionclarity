package clients

type Client interface {
	ResolvePackageType(funcIdentifier string) (string, error)
	GetFuncCode(funcIdentifier string) (string, error)
	GetFuncImageURI(funcIdentifier string) (string, error)
	Upload(signature string, identity string) error
	Download(identity string) (string, error)
}
