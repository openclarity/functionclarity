package options

import "github.com/spf13/cobra"

type SigningOptions struct {
	Key string
}

func (o *SigningOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Key, "key", "",
		"key for signing")
	cmd.MarkFlagRequired("key")
}
