package integrity

import (
	"os"
	"path/filepath"
)

func ReadFile(path string) ([]byte, error) {
	var raw []byte
	var err error
	raw, err = os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return raw, nil
}
