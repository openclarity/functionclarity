package verify

import (
	"context"
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/verify"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
	"github.com/openclarity/function-clarity/pkg/options"
	v "github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"log"
)

func Verify(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context, action string) error {
	packageType, err := client.ResolvePackageType(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to resolve package type for function: %s. %v", functionIdentifier, err)
	}
	switch packageType {
	case "Zip":
		err = verifyCode(client, functionIdentifier, o, ctx)
	case "Image":
		err = verifyImage(client, functionIdentifier, o, ctx)
	default:
		return fmt.Errorf("unsupported package type: %s for function: %s. %v", packageType, functionIdentifier, err)
	}
	return HandleVerification(client, action, functionIdentifier, err != nil)
}

func HandleVerification(client clients.Client, action string, funcIdentifier string, failed bool) error {
	switch action {
	case "":
		log.Printf("no action defined, nothing to do")
		return nil
	case "notify":
		log.Printf("handle notify")
		return nil
	case "block":
		return client.HandleBlock(&funcIdentifier, failed)
	default:
		return client.HandleDetect(&funcIdentifier, failed)
	}
}

func verifyImage(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context) error {
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

	vc := v.VerifyCommand{
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

	return vc.Exec(ctx, []string{imageURI})
}

func verifyCode(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context) error {
	codePath, err := client.GetFuncCode(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to fetch function code for function: %s. %v", functionIdentifier, err)
	}
	integrityCalculator := integrity.Sha256{}
	functionIdentity, err := integrityCalculator.GenerateIdentity(codePath)
	if err != nil {
		return fmt.Errorf("failed to generate function identity for function: %s. %v", functionIdentifier, err)
	}

	isKeyless := false
	if !o.SecurityKey.Use && o.Key == "" && o.BundlePath == "" && integrity.IsExperimentalEnv() {
		isKeyless = true
	}
	if err = downloadSignatureAndCertificate(client, functionIdentifier, err, functionIdentity, isKeyless); err != nil {
		return err
	}
	if err = verify.VerifyIdentity(functionIdentity, o, ctx, isKeyless); err != nil {
		return err
	}
	return nil
}

func downloadSignatureAndCertificate(client clients.Client, functionIdentifier string, err error, functionIdentity string, isKeyless bool) error {
	if err = client.Download(functionIdentity, "sig"); err != nil {
		return fmt.Errorf("failed to get signed identity for function: %s. %v", functionIdentifier, err)
	}
	if isKeyless {
		if err = client.Download(functionIdentity, "crt.base64"); err != nil {
			return fmt.Errorf("failed to get certificate for function: %s. %v", functionIdentifier, err)
		}
	}
	return nil
}
