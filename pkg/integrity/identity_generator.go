package integrity

import (
	"crypto/sha256"
	"fmt"
	"log"
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
	err := filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				data, err := os.ReadFile(path)
				if err != nil {
					fmt.Println("File reading error", err)
				}
				dataString := fmt.Sprintf("%x", data)
				dataString = dataString + path[strings.Index(path, rootFolderName)+len(rootFolderName):]
				sha := sha256.Sum256([]byte(dataString))
				fmt.Printf("%s %x\n", path[strings.Index(path, rootFolderName)+len(rootFolderName):], sha)
				identities = append(identities, fmt.Sprintf("%x", sha))
			} else if rootFolderName == "" {
				rootFolderName = info.Name()
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}
	sort.Strings(identities)
	joinedShaString := strings.Join(identities[:], ",")
	identitiesSha256 := sha256.Sum256([]byte(joinedShaString))
	return fmt.Sprintf("%x", identitiesSha256), nil
}
