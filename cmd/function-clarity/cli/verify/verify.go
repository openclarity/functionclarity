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

package verify

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/openclarity/function-clarity/pkg/integrity"
	opts "github.com/openclarity/function-clarity/pkg/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func VerifyIdentity(identity string, o *opts.VerifyOpts, ctx context.Context, isKeyless bool) error {
	path := "/tmp/" + uuid.New().String()
	if err := integrity.SaveTextToFile(identity, path); err != nil {
		return err
	}

	ko := options.KeyOpts{
		KeyRef:     o.Key,
		Sk:         o.SecurityKey.Use,
		Slot:       o.SecurityKey.Slot,
		RekorURL:   o.Rekor.URL,
		BundlePath: o.BundlePath,
	}

	certRef := o.CertVerify.Cert
	if isKeyless {
		certRef = "/tmp/" + identity + ".crt.base64"
	}
	sigRef := "/tmp/" + identity + ".sig"

	if err := verify.VerifyBlobCmd(ctx, ko, certRef,
		o.CertVerify.CertEmail, o.CertVerify.CertOidcIssuer, o.CertVerify.CertChain,
		sigRef, path, o.CertVerify.CertGithubWorkflowTrigger, o.CertVerify.CertGithubWorkflowSha,
		o.CertVerify.CertGithubWorkflowName, o.CertVerify.CertGithubWorkflowRepository, o.CertVerify.CertGithubWorkflowRef,
		o.CertVerify.EnforceSCT); err != nil {
		return fmt.Errorf("verifying identity %s: %w", identity, err)
	}
	return nil
}
