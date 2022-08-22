package options

import "github.com/spf13/cobra"

type AwsOptions struct {
	AccessKey      string
	SecretKey      string
	Bucket         string
	Region         string
	SigningOptions SigningOptions
}

func (o *AwsOptions) AddFlags(cmd *cobra.Command) {
	o.SigningOptions.AddFlags(cmd)
	cmd.Flags().StringVar(&o.SecretKey, "aws-secret-key", "",
		"aws secret key")

	cmd.Flags().StringVar(&o.AccessKey, "aws-access-key", "",
		"aws access key")

	cmd.Flags().StringVar(&o.Region, "region", "",
		"aws region to perform the operation against")

	cmd.Flags().StringVar(&o.Bucket, "bucket", "",
		"s3 bucket to work against")
	cmd.MarkFlagRequired("bucket")
}