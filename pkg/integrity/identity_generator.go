// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
