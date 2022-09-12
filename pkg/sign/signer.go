package sign

import (
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/sign"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
	"github.com/openclarity/function-clarity/pkg/options"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/viper"
)

func SignAndUploadCode(client clients.Client, codePath string, o *options.SignBlobOptions, ro *co.RootOptions) error {
	hash := new(integrity.Sha256)
	codeIdentity, err := hash.GenerateIdentity(codePath)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	fmt.Printf("code identity: %s", codeIdentity)
	isKeyless := false
	privateKey := viper.GetString("privatekey")
	if !o.SecurityKey.Use && privateKey == "" && integrity.IsExperimentalEnv() {
		isKeyless = true
	}

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
