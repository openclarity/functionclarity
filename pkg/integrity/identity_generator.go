package integrity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type IdentityGenerator interface {
	GenerateIdentity(path string) (string, error)
}

type Sha256 struct{}

func (o *Sha256) GenerateIdentity(path string) (string, error) {
	var identities []string
	rootFolderName := ""
	err := filepath.WalkDir(path,
		func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				dataString := fmt.Sprintf("%x", data)
				if rootFolderName == "" {
					dataString = dataString + d.Name()
				} else {
					dataString = dataString + path[strings.Index(path, rootFolderName)+len(rootFolderName)+1:]
				}
				sha := sha256.Sum256([]byte(dataString))
				identities = append(identities, fmt.Sprintf("%x", sha))
			} else if rootFolderName == "" {
				rootFolderName = d.Name()
			}
			return nil
		})
	if err != nil {
		return "", err
	}
	sort.Strings(identities)
	joinedShaString := strings.Join(identities[:], ",")
	identitiesSha256 := sha256.Sum256([]byte(joinedShaString))
	return fmt.Sprintf("%x", identitiesSha256), nil
}
