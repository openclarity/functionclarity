package options

import (
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

type SignOptions struct {
	options.SignOptions
}

func (o *SignOptions) AddFlags(cmd *cobra.Command) {
	o.Rekor.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Cert, "certificate", "",
		"path to the X.509 certificate in PEM format to include in the OCI Signature")

	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA X.509 certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate. Included in the OCI Signature")

	cmd.Flags().BoolVar(&o.Upload, "upload", true,
		"whether to upload the signature")

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")

	cmd.Flags().StringVar(&o.OutputCertificate, "output-certificate", "",
		"write the certificate to FILE")

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"skip warnings and confirmations")

	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false,
		"if a multi-arch image is specified, additionally sign each discrete image")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")

	cmd.Flags().BoolVar(&o.NoTlogUpload, "no-tlog-upload", false,
		"whether to not upload the transparency log")
}
