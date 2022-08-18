package clients

type SignatureClient interface {
	Upload(signature string, identity string) error
	Download(identity string) (string, error)
}
