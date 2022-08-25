package aws

import (
	"flag"
	"fmt"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/cobra"
)

func AwsSignImage() *cobra.Command {
	o := &co.SignOptions{}
	ro := &co.RootOptions{}

	cmd := &cobra.Command{
		Use:   "image",
		Short: "sign and upload the image digest to aws",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch o.Attachment {
			case "sbom", "":
				break
			default:
				return flag.ErrHelp
			}
			oidcClientSecret, err := o.OIDC.ClientSecret()
			if err != nil {
				return err
			}
			ko := co.KeyOpts{
				KeyRef:                   o.Key,
				PassFunc:                 generate.GetPass,
				Sk:                       o.SecurityKey.Use,
				Slot:                     o.SecurityKey.Slot,
				FulcioURL:                o.Fulcio.URL,
				IDToken:                  o.Fulcio.IdentityToken,
				InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                 o.Rekor.URL,
				OIDCIssuer:               o.OIDC.Issuer,
				OIDCClientID:             o.OIDC.ClientID,
				OIDCClientSecret:         oidcClientSecret,
				OIDCRedirectURL:          o.OIDC.RedirectURL,
				OIDCDisableProviders:     o.OIDC.DisableAmbientProviders,
				OIDCProvider:             o.OIDC.Provider,
				SkipConfirmation:         o.SkipConfirmation,
			}
			annotationsMap, err := o.AnnotationsMap()
			if err != nil {
				return err
			}
			if err := sign.SignCmd(ro, ko, o.Registry, annotationsMap.Annotations, args, o.Cert, o.CertChain, o.Upload,
				o.OutputSignature, o.OutputCertificate, o.PayloadPath, o.Force, o.Recursive, o.Attachment, o.NoTlogUpload); err != nil {
				if o.Attachment == "" {
					return fmt.Errorf("signing %v: %w", args, err)
				}
				return fmt.Errorf("signing attachment %s for image %v: %w", o.Attachment, args, err)
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	ro.AddFlags(cmd)
	return cmd
}
