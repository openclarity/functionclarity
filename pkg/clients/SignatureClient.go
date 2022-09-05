package clients

type SignatureClient interface {
	Upload(signature string, identity string, isKeyless bool) error
	Download(fileName string, outputType string) error
}
