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

package options

import (
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

type VerifyOpts struct {
	BundlePath string
	co.VerifyOptions
}

func (o *VerifyOpts) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.SignatureDigest.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the signing image information (json|text)")

	cmd.Flags().StringVar(&o.SignatureRef, "signature", "",
		"signature content or path or remote URL")

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a path to an image saved locally via 'cosign save'")

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to bundle FILE")
}
