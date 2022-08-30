package aws

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/sign"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func AwsSignCode() *cobra.Command {
	awsOptions := &options.AwsOptions{}
	o := &co.SignBlobOptions{}
	ro := &co.RootOptions{}

	cmd := &cobra.Command{
		Use:   "code",
		Short: "sign and upload the code content to aws",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			awsClient := clients.NewAwsClient(awsOptions.AccessKey, awsOptions.SecretKey, awsOptions.Bucket, awsOptions.Region)
			sign.SignAndUploadCode(awsClient, args[0], o, ro)
		},
	}
	awsOptions.AddFlags(cmd)
	o.AddFlags(cmd)
	ro.AddFlags(cmd)

	return cmd
}
