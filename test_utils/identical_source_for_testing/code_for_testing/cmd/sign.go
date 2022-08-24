//go:build ignore

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func Sign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "sign and upload the code content",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println("sign") },
	}

	return cmd
}
