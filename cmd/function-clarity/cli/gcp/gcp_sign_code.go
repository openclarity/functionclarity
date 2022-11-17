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

	"github.com/openclarity/functionclarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/functionclarity/pkg/clients"
	o "github.com/openclarity/functionclarity/pkg/options"
	"github.com/openclarity/functionclarity/pkg/sign"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func GCPSignCode() *cobra.Command {
	sbo := &o.SignBlobOptions{}
	ro := &co.RootOptions{}

	cmd := &cobra.Command{
		Use:   "code",
		Short: "sign code content and upload its signature to GCP",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("location", cmd.Flags().Lookup("location")); err != nil {
				return fmt.Errorf("error binding location: %w", err)
			}
			if err := viper.BindPFlag("bucket", cmd.Flags().Lookup("bucket")); err != nil {
				return fmt.Errorf("error binding bucket: %w", err)
			}
			if err := viper.BindPFlag("privatekey", cmd.Flags().Lookup("key")); err != nil {
				return fmt.Errorf("error binding privatekey: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			gcpProperties := clients.NewGCPClientInit(viper.GetString("bucket"), viper.GetString("location"), "")
			return sign.SignAndUploadCode(gcpProperties, args[0], sbo, ro)
		},
	}
	initGCPSignCodeFlags(cmd)
	sbo.AddFlags(cmd)
	ro.AddFlags(cmd)
	return cmd
}

func initGCPSignCodeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&options.Config, "config", "", "config file (default: $HOME/.fs)")
	cmd.Flags().String("location", "", "GCP location to perform the operation against")
	cmd.Flags().String("bucket", "", "cloud storage bucket to work against")
	cmd.Flags().String("key", "", "private key")
}
