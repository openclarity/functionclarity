package aws

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
	o "github.com/openclarity/function-clarity/pkg/options"
	"github.com/openclarity/function-clarity/pkg/sign"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
)

func AwsSignCode() *cobra.Command {
	sbo := &o.SignBlobOptions{}
	ro := &co.RootOptions{}

	cmd := &cobra.Command{
		Use:   "code",
		Short: "sign and upload the code content to aws",
		Args:  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			if err := viper.BindPFlag("accessKey", cmd.Flags().Lookup("aws-access-key")); err != nil {
				log.Fatal(err)
			}
			if err := viper.BindPFlag("secretKey", cmd.Flags().Lookup("aws-secret-key")); err != nil {
				log.Fatal(err)
			}
			if err := viper.BindPFlag("region", cmd.Flags().Lookup("region")); err != nil {
				log.Fatal(err)
			}
			if err := viper.BindPFlag("bucket", cmd.Flags().Lookup("bucket")); err != nil {
				log.Fatal(err)
			}
			if err := viper.BindPFlag("privatekey", cmd.Flags().Lookup("key")); err != nil {
				log.Fatal(err)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			awsClient := clients.NewAwsClient(viper.GetString("accesskey"), viper.GetString("secretkey"), viper.GetString("bucket"), viper.GetString("region"), "")
			return sign.SignAndUploadCode(awsClient, args[0], sbo, ro)
		},
	}
	initAwsSignCodeFlags(cmd)
	sbo.AddFlags(cmd)
	ro.AddFlags(cmd)
	return cmd
}

func initAwsSignCodeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&options.Config, "config", "", "config file (default: $HOME/.fs)")
	cmd.Flags().String("aws-access-key", "", "aws access key")
	cmd.Flags().String("aws-secret-key", "", "aws secret key")
	cmd.Flags().String("region", "", "aws region to perform the operation against")
	cmd.Flags().String("bucket", "", "s3 bucket to work against")
	cmd.Flags().String("key", "", "private key")
}
