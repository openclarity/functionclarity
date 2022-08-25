package cli

import (
	"fmt"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/aws"
	"github.com/spf13/cobra"
)

func Verify() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "verify code content integrity",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println("verify") },
	}
	cmd.AddCommand(aws.AwsVerify())
	return cmd
}
