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

package aws

import (
	"flag"
	"fmt"

	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	opt "github.com/openclarity/function-clarity/pkg/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func AwsSignImage() *cobra.Command {
	o := &opt.SignOptions{}
	ro := &co.RootOptions{}

	cmd := &cobra.Command{
		Use:   "image",
		Short: "sign and upload the image digest to aws",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("privatekey", cmd.Flags().Lookup("key")); err != nil {
				return fmt.Errorf("error binding privatekey: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch o.Attachment {
			case "sbom", "":
				break
			default:
				return flag.ErrHelp
			}
			oidcClientSecret, err := o.OIDC.ClientSecret()
			if err != nil {
				return err
			}
			ko := co.KeyOpts{
				KeyRef:                   viper.GetString("privatekey"),
				PassFunc:                 generate.GetPass,
				Sk:                       o.SecurityKey.Use,
				Slot:                     o.SecurityKey.Slot,
				FulcioURL:                o.Fulcio.URL,
				IDToken:                  o.Fulcio.IdentityToken,
				InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                 o.Rekor.URL,
				OIDCIssuer:               o.OIDC.Issuer,
				OIDCClientID:             o.OIDC.ClientID,
				OIDCClientSecret:         oidcClientSecret,
				OIDCRedirectURL:          o.OIDC.RedirectURL,
				OIDCDisableProviders:     o.OIDC.DisableAmbientProviders,
				OIDCProvider:             o.OIDC.Provider,
				SkipConfirmation:         o.SkipConfirmation,
			}
			annotationsMap, err := o.AnnotationsMap()
			if err != nil {
				return err
			}
			if err := sign.SignCmd(ro, ko, o.Registry, annotationsMap.Annotations, args, o.Cert, o.CertChain, o.Upload,
				o.OutputSignature, o.OutputCertificate, o.PayloadPath, o.Force, o.Recursive, o.Attachment, o.NoTlogUpload); err != nil {
				if o.Attachment == "" {
					return fmt.Errorf("signing %v: %w", args, err)
				}
				return fmt.Errorf("signing attachment %s for image %v: %w", o.Attachment, args, err)
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	ro.AddFlags(cmd)
	initAwsSignImageFlags(cmd)
	return cmd
}

func initAwsSignImageFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&options.Config, "config", "", "config file (default: $HOME/.fs)")
	cmd.Flags().String("key", "", "private key")
}
