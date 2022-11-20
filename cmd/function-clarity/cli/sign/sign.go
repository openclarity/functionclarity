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

package sign

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/openclarity/functionclarity/pkg/integrity"
	o "github.com/openclarity/functionclarity/pkg/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	co "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/viper"
)

func SignIdentity(identity string, o *o.SignBlobOptions, ro *co.RootOptions, isKeyless bool) (string, error) {
	path := "/tmp/" + uuid.New().String()
	if err := integrity.SaveTextToFile(identity, path); err != nil {
		return "", fmt.Errorf("signing identity: %w", err)
	}

	oidcClientSecret, err := o.OIDC.ClientSecret()
	if err != nil {
		return "", fmt.Errorf("signing identity: %w", err)
	}
	ko := options.KeyOpts{
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
		BundlePath:               o.BundlePath,
		SkipConfirmation:         o.SkipConfirmation,
	}
	outputSignature := o.OutputSignature
	outputCertificate := o.OutputCertificate
	if isKeyless {
		outputSignature = "/tmp/" + identity + ".sig"
		outputCertificate = "/tmp/" + identity + ".crt.base64"
	}

	sig, err := sign.SignBlobCmd(ro, ko, o.Registry, path, o.Base64Output, outputSignature, outputCertificate)

	if err != nil {
		return "", fmt.Errorf("signing identity: %w", err)
	}

	return string(sig), nil

}
