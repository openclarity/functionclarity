package verify

import (
	"context"
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/verify"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	v "github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func Verify(client clients.Client, functionIdentifier string, o *co.VerifyOptions, ctx context.Context) error {
	packageType, err := client.ResolvePackageType(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to resolve package type for function: %s. %v", functionIdentifier, err)
	}
	switch packageType {
	case "Zip":
		return verifyCode(client, functionIdentifier, o.Key)
	case "Image":
		return verifyImage(client, functionIdentifier, o, ctx)
	default:
		return fmt.Errorf("unsupported package type: %s for function: %s. %v", packageType, functionIdentifier, err)
	}
}

func verifyImage(client clients.Client, functionIdentifier string, o *co.VerifyOptions, ctx context.Context) error {
	imageURI, err := client.GetFuncImageURI(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to fetch function image URI for function: %s. %v", functionIdentifier, err)
	}
	annotations, err := o.AnnotationsMap()
	if err != nil {
		return err
	}

	hashAlgorithm, err := o.SignatureDigest.HashAlgorithm()
	if err != nil {
		return err
	}

	v := v.VerifyCommand{
		RegistryOptions:              o.Registry,
		CheckClaims:                  o.CheckClaims,
		KeyRef:                       o.Key,
		CertRef:                      o.CertVerify.Cert,
		CertEmail:                    o.CertVerify.CertEmail,
		CertOidcIssuer:               o.CertVerify.CertOidcIssuer,
		CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        o.CertVerify.CertGithubWorkflowSha,
		CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
		CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
		CertChain:                    o.CertVerify.CertChain,
		EnforceSCT:                   o.CertVerify.EnforceSCT,
		Sk:                           o.SecurityKey.Use,
		Slot:                         o.SecurityKey.Slot,
		Output:                       o.Output,
		RekorURL:                     o.Rekor.URL,
		Attachment:                   o.Attachment,
		Annotations:                  annotations,
		HashAlgorithm:                hashAlgorithm,
		SignatureRef:                 o.SignatureRef,
		LocalImage:                   o.LocalImage,
	}

	return v.Exec(ctx, []string{imageURI})
}

func verifyCode(client clients.Client, functionIdentifier string, key string) error {
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
	err = verify.VerifyIdentity(key, signedIdentity, functionIdentity)
	if err != nil {
		return err
	}
	return nil
}
