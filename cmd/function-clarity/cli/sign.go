package cli

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/aws"
	"github.com/spf13/cobra"
)

type SignOptions struct {
	key string
}

func Sign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "sign and upload the code content",
	}
	cmd.AddCommand(aws.AwsSign())
	return cmd
}
