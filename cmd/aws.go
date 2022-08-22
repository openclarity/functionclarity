package cmd

import (
	"github.com/openclarity/function-clarity/cmd/options"
	"github.com/openclarity/function-clarity/pkg"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/spf13/cobra"
)

func AwsSign() *cobra.Command {
	awsOptions := &options.AwsOptions{}

	cmd := &cobra.Command{
		Use:   "aws",
		Short: "sign and upload the code content to aws",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			awsClient := clients.NewAwsClient(awsOptions.AccessKey, awsOptions.SecretKey, awsOptions.Bucket, awsOptions.Region)
			pkg.SignAndUpload(awsClient, args[0], awsOptions.SigningOptions.Key)
		},
	}
	awsOptions.AddFlags(cmd)

	return cmd
}
