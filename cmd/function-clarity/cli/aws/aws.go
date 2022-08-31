package aws

import (
	"fmt"
	opts "github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
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

type Input struct {
	AccessKey string
	SecretKey string
	Region    string
}

func AwsInit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "initialize configuration in aws",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getParameters()
			if err != nil {
				return err
			}
			clients.NewAwsClientInit(parameters.AccessKey, parameters.SecretKey, parameters.Region)
			//int cloud formation
			return nil
		},
	}
	return cmd
}

func getParameters() (*Input, error) {
	var input Input
	if err := inputParameter("Enter Access Key: ", &input.AccessKey); err != nil {
		return nil, err
	}
	if err := inputParameter("Enter Secret Key: ", &input.SecretKey); err != nil {
		return nil, err
	}
	if err := inputParameter("Enter region: ", &input.Region); err != nil {
		return nil, err
	}
	return &input, nil
}

func inputParameter(q string, p *string) error {
	fmt.Println(q)
	_, err := fmt.Scanln(p)
	return err
}
