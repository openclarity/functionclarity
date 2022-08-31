package aws

import (
	opts "github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
	i "github.com/openclarity/function-clarity/pkg/init"
	"github.com/openclarity/function-clarity/pkg/options"
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
	awsOptions := &opts.AwsOptions{}
	o := &options.VerifyOpts{}
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

func AwsInit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "initialize configuration in aws",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var input i.Input
			if err := input.RecieveParameters(); err != nil {
				return err
			}
			clients.NewAwsClientInit(input.AccessKey, input.SecretKey, input.Region)
			//int cloud formation
			return nil
		},
	}
	return cmd
}
