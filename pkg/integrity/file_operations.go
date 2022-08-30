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

func SaveTextToFile(text string, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		return err
	}
	return nil
}
