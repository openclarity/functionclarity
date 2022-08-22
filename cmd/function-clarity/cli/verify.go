package cli

import (
	"fmt"
	"github.com/spf13/cobra"
)

func Verify() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "verify code content integrity",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println("verify") },
	}
	cmd.AddCommand(AwsVerify())
	return cmd
}
