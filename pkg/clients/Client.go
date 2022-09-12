package clients

type Client interface {
	ResolvePackageType(funcIdentifier string) (string, error)
	GetFuncCode(funcIdentifier string) (string, error)
	GetFuncImageURI(funcIdentifier string) (string, error)
	Upload(signature string, identity string, isKeyless bool) error
	Download(fileName string, outputType string) error
	HandleBlock(funcIdentifier *string, failed bool) error
	HandleDetect(funcIdentifier *string, failed bool) error
	Notify(msg string, snsArn string) error
}
