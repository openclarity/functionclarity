package cmd

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

	return cmd
}
