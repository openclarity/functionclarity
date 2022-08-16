package integrity

type Hash interface {
	Hash(path string) (string, error)
}
