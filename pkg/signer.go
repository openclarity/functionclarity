package pkg

import (
	"fmt"
	"function-clarity/pkg/clients"
	"function-clarity/pkg/integrity"
)

func SignAndUpload(client clients.SignatureClient, folderPath string, key string) error {
	hash := new(integrity.Sha256)
	codeIdentifier, err := hash.Hash(folderPath)
	if err != nil {
		return fmt.Errorf("failed to create identity for folder: %s", folderPath)
	}
	//run the signing command here
	err = client.Upload(codeIdentifier, codeIdentifier+".sig")
	if err != nil {
		return fmt.Errorf("failed to upload code signature")
	}
	return nil
}
