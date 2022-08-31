package cli

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/aws"
	"github.com/spf13/cobra"
)

func Init() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "init cloud provider configuration",
	}
	cmd.AddCommand(aws.AwsInit())
	return cmd
}
