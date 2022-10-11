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

package sign

import (
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/sign"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
	"github.com/openclarity/function-clarity/pkg/options"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/viper"
	"log"
)

func SignAndUploadCode(client clients.Client, codePath string, o *options.SignBlobOptions, ro *co.RootOptions) error {
	hash := new(integrity.Sha256)
	codeIdentity, err := hash.GenerateIdentity(codePath)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	isKeyless := false
	privateKey := viper.GetString("privatekey")
	if !o.SecurityKey.Use && privateKey == "" && integrity.IsExperimentalEnv() {
		isKeyless = true
	}

	log.Printf("privateKey: %v\n", privateKey)
	log.Printf("publicKey: %v\n", viper.GetString("publickey"))
	log.Printf("IsExperimentalEnv: %v\n", integrity.IsExperimentalEnv())
	log.Printf("isKeyless: %v\n", isKeyless)

	signedIdentity, err := sign.SignIdentity(codeIdentity, o, ro, isKeyless)
	if err != nil {
		return fmt.Errorf("failed to sign identity: %s with private key in path: %s: %w", codeIdentity, privateKey, err)
	}
	if err = client.Upload(signedIdentity, codeIdentity, isKeyless); err != nil {
		return fmt.Errorf("failed to upload code signature: identity: %s, signature: %s to bucket: %s: %w", codeIdentity, signedIdentity, viper.GetString("bucket"), err)
	}
	fmt.Println("Code uploaded successfully")
	return nil
}
