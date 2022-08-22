package verify

import (
	"fmt"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
)

func Verify(client clients.Client, functionIdentifier string, key string) error {
	codePath, err := client.GetFuncCode(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to fetch function code for function: %s. %v", functionIdentifier, err)
	}
	integrityCalculator := integrity.Sha256{}
	functionIdentity, err := integrityCalculator.GenerateIdentity(codePath)
	if err != nil {
		return fmt.Errorf("failed to generate function identity for function: %s. %v", functionIdentifier, err)
	}
	signedIdentity, err := client.Download(functionIdentity + ".sig")
	if err != nil {
		return fmt.Errorf("failed to get signed identity for function: %s. %v", functionIdentifier, err)
	}
	//todo: Roman code here instead of the next line
	fmt.Printf(signedIdentity)
	return nil
}
