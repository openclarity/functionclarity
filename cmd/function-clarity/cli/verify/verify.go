package verify

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/openclarity/function-clarity/pkg/integrity"
	opts "github.com/openclarity/function-clarity/pkg/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func VerifyIdentity(signature string, identity string, o *opts.VerifyOpts, ctx context.Context) error {
	path := "/tmp/" + uuid.New().String()
	if err := integrity.SaveTextToFile(identity, path); err != nil {
		return err
	}

	ko := options.KeyOpts{
		KeyRef:     o.Key,
		Sk:         o.SecurityKey.Use,
		Slot:       o.SecurityKey.Slot,
		RekorURL:   o.Rekor.URL,
		BundlePath: o.BundlePath,
	}
	if err := verify.VerifyBlobCmd(ctx, ko, o.CertVerify.Cert,
		o.CertVerify.CertEmail, o.CertVerify.CertOidcIssuer, o.CertVerify.CertChain,
		signature, path, o.CertVerify.CertGithubWorkflowTrigger, o.CertVerify.CertGithubWorkflowSha,
		o.CertVerify.CertGithubWorkflowName, o.CertVerify.CertGithubWorkflowRepository, o.CertVerify.CertGithubWorkflowRef,
		o.CertVerify.EnforceSCT); err != nil {
		return fmt.Errorf("verifying identity: %s, %w", identity, err)
	}
	return nil
}
