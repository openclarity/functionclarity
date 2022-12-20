// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcp

import (
	"fmt"

	"github.com/openclarity/functionclarity/cmd/function-clarity/cli/common"
	opt "github.com/openclarity/functionclarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/functionclarity/pkg/clients"
	"github.com/openclarity/functionclarity/pkg/options"
	"github.com/openclarity/functionclarity/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func GcpSign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gcp",
		Short: "sign code/image and upload to GCP",
	}
	cmd.AddCommand(GCPSignCode())
	cmd.AddCommand(common.SignImage())
	return cmd
}

func GcpVerify() *cobra.Command {
	o := &options.VerifyOpts{}
	var functionRegion string
	cmd := &cobra.Command{
		Use:   "gcp",
		Short: "verify function identity",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("location", cmd.Flags().Lookup("location")); err != nil {
				return fmt.Errorf("error binding location: %w", err)
			}
			if err := viper.BindPFlag("bucket", cmd.Flags().Lookup("bucket")); err != nil {
				return fmt.Errorf("error binding bucket: %w", err)
			}
			if err := viper.BindPFlag("publickey", cmd.Flags().Lookup("key")); err != nil {
				return fmt.Errorf("error binding publickey: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Key = viper.GetString("publickey")
			gcpClient := clients.NewGCPClientInit(viper.GetString("bucket"), viper.GetString("location"), functionRegion)
			_, _, err := verify.Verify(gcpClient, args[0], o, cmd.Context(), "", "", nil, nil, "")
			return err
		},
	}
	cmd.Flags().StringVar(&functionRegion, "function-location", "", "GCP location where the verified function runs")
	cmd.MarkFlagRequired("function-region") //nolint:errcheck
	o.AddFlags(cmd)
	initGCPVerifyFlags(cmd)
	return cmd
}

func initGCPVerifyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&opt.Config, "config", "", "config file (default: $HOME/.fs)")
	cmd.Flags().String("location", "", "GCP location to perform the operation against")
	cmd.Flags().String("bucket", "", "GCP bucket to work against")
	cmd.Flags().String("key", "", "public key")
}
