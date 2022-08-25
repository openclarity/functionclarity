package sign

import (
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/sign"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
)

func SignAndUploadCode(client clients.SignatureClient, codePath string, keyPath string) error {
	hash := new(integrity.Sha256)
	codeIdentity, err := hash.GenerateIdentity(codePath)
	if err != nil {
		return fmt.Errorf("failed to create identity for folder: %s", codePath)
	}
	signedIdentity, err := sign.SignIdentity(keyPath, codeIdentity)
	if err != nil {
		return fmt.Errorf("failed to sign identity: %s with private key in path: %s", codeIdentity, keyPath)
	}
	err = client.Upload(signedIdentity, codeIdentity+".sig")
	if err != nil {
		return fmt.Errorf("failed to upload code signature")
	}
	return nil
}
