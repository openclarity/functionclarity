package aws

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/verify"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
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
	o := &co.VerifyOptions{}
	var functionIdentifier string
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "verify function identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			awsClient := clients.NewAwsClient(awsOptions.AccessKey, awsOptions.SecretKey, awsOptions.Bucket, awsOptions.Region)
			return verify.Verify(awsClient, args[0], o, cmd.Context())
		},
	}
	cmd.Flags().StringVar(&functionIdentifier, "function-identifier", "",
		"function to verify")
	awsOptions.AddFlags(cmd)
	o.AddFlags(cmd)

	return cmd
}
