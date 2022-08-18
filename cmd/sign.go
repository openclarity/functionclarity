package cmd

import (
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
	cmd.AddCommand(AwsSign())
	return cmd
}
