package sign

import (
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/sign"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func SignAndUploadCode(client clients.Client, codePath string, o *co.SignBlobOptions, ro *co.RootOptions) error {
	hash := new(integrity.Sha256)
	codeIdentity, err := hash.GenerateIdentity(codePath)
	fmt.Printf("code identity: %s", codeIdentity)
	if err != nil {
		return fmt.Errorf("failed to create identity: %v", err)
	}
	isKeyless := false
	if !o.SecurityKey.Use && o.Key == "" && integrity.IsExperimentalEnv() {
		isKeyless = true
	}

	signedIdentity, err := sign.SignIdentity(codeIdentity, o, ro, isKeyless)
	if err != nil {
		return fmt.Errorf("failed to sign identity: %s with private key in path: %s", codeIdentity, o.Key)
	}
	if err = client.Upload(signedIdentity, codeIdentity, isKeyless); err != nil {
		return fmt.Errorf("failed to upload code signature")
	}
	fmt.Println("Code uploaded successfully")
	return nil
}
