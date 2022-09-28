package cli

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/aws"
	"github.com/spf13/cobra"
)

func Deploy() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy function clarity to cloud provider",
	}
	cmd.AddCommand(aws.AwsDeploy())
	return cmd
}
