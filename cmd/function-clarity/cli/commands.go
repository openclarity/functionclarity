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
