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

func VerifyIdentity(identity string, o *opts.VerifyOpts, ctx context.Context, isKeyless bool) error {
	path := "/tmp/" + uuid.New().String()
	if err := integrity.SaveTextToFile(identity, path); err != nil {
		return err
	}

	ko := options.KeyOpts{
		KeyRef:     o.PublicKey,
		Sk:         o.SecurityKey.Use,
		Slot:       o.SecurityKey.Slot,
		RekorURL:   o.Rekor.URL,
		BundlePath: o.BundlePath,
	}

	certRef := o.CertVerify.Cert
	if isKeyless {
		certRef = "/tmp/" + identity + ".crt.base64"
	}
	sigRef := "/tmp/" + identity + ".sig"

	if err := verify.VerifyBlobCmd(ctx, ko, certRef,
		o.CertVerify.CertEmail, o.CertVerify.CertOidcIssuer, o.CertVerify.CertChain,
		sigRef, path, o.CertVerify.CertGithubWorkflowTrigger, o.CertVerify.CertGithubWorkflowSha,
		o.CertVerify.CertGithubWorkflowName, o.CertVerify.CertGithubWorkflowRepository, o.CertVerify.CertGithubWorkflowRef,
		o.CertVerify.EnforceSCT); err != nil {
		return fmt.Errorf("verifying identity: %s, %w", identity, err)
	}
	return nil
}
