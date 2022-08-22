package integrity

type Hash interface {
	GenerateIdentity(path string) (string, error)
}
