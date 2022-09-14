package cli

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/aws"
	"github.com/spf13/cobra"
)

func Verify() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "verify function's code/image integrity",
	}
	cmd.AddCommand(aws.AwsVerify())
	return cmd
}
