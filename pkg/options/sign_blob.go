package options

import (
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

type SignBlobOptions struct {
	options.SignBlobOptions
}

func (o *SignBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.Registry.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.Base64Output, "b64", true,
		"whether to base64 encode the output")

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")

	cmd.Flags().StringVar(&o.Output, "output", "", "write the signature to FILE")

	cmd.Flags().StringVar(&o.OutputCertificate, "output-certificate", "",
		"write the certificate to FILE")

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"write everything required to verify the blob to a FILE")

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")
}
