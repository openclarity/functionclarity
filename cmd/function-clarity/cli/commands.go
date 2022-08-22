package cli

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "function-clarity",
		Short: "cli for signing and verifying function content",
		Long:  `cli for signing and verifying function content`,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		//Run: func(cmd *cobra.Command, args []string) { fmt.Println("aaaa") },
	}

	cmd.AddCommand(Sign())
	cmd.AddCommand(Verify())
	return cmd
}
