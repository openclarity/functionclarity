package cli

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "function-clarity",
		Short: "cli for signing and verifying function content",
		Long:  `cli for signing and verifying function content`,
	}

	cmd.AddCommand(Sign())
	cmd.AddCommand(Verify())
	cmd.AddCommand(cli.GenerateKeyPair())
	cmd.AddCommand(cli.ImportKeyPair())
	cmd.AddCommand(Init())
	cobra.OnInitialize(options.CobraInit)
	return cmd
}
