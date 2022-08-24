package cli

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/verify"
	"github.com/spf13/cobra"
)

func AwsSign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "sign content from aws",
	}
	cmd.AddCommand(AwsSignCode())
	cmd.AddCommand(AwsSignImage())
	return cmd
}

func AwsVerify() *cobra.Command {
	awsOptions := &options.AwsOptions{}
	var functionIdentifier string
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "verify function identity",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			awsClient := clients.NewAwsClient(awsOptions.AccessKey, awsOptions.SecretKey, awsOptions.Bucket, awsOptions.Region)
			verify.Verify(awsClient, args[0], awsOptions.SigningOptions.Key)
		},
	}
	cmd.Flags().StringVar(&functionIdentifier, "function-identifier", "",
		"function to verify")
	awsOptions.AddFlags(cmd)

	return cmd
}
