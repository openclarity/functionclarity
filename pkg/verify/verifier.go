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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/verify"
	"github.com/openclarity/function-clarity/pkg/clients"
	"github.com/openclarity/function-clarity/pkg/integrity"
	"github.com/openclarity/function-clarity/pkg/options"
	v "github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func Verify(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context,
	action string, topicArn string, region string, tagKeysFilter []string, filteredRegions []string) error {

	if filteredRegions != nil && (len(filteredRegions) > 0) {
		funcInRegions := client.IsFuncInRegions(filteredRegions)
		if !funcInRegions {
			fmt.Printf("function: %s not in regions list: %s, skipping validation", functionIdentifier, filteredRegions)
			return nil
		}
	}

	if tagKeysFilter != nil && (len(tagKeysFilter) > 0) {
		funcContainsTag, err := client.FuncContainsTags(functionIdentifier, tagKeysFilter)
		if err != nil {
			return fmt.Errorf("check function tags: failed to check tags of function: %s: %w", functionIdentifier, err)
		}
		if !funcContainsTag {
			fmt.Printf("function: %s doesn't contain tag in the list: %s, skipping validation", functionIdentifier, tagKeysFilter)
			return nil
		}
	}
	packageType, err := client.ResolvePackageType(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to resolve package type for function: %s: %w", functionIdentifier, err)
	}
	switch packageType {
	case "Zip":
		err = verifyCode(client, functionIdentifier, o, ctx)
	case "Image":
		err = verifyImage(client, functionIdentifier, o, ctx)
	default:
		return fmt.Errorf("unsupported package type: %s for function: %s", packageType, functionIdentifier)
	}
	return HandleVerification(client, action, functionIdentifier, err, topicArn, region)
}

func HandleVerification(client clients.Client, action string, funcIdentifier string, err error, topicArn string, region string) error {
	if err != nil && !errors.Is(err, VerifyError{}) {
		return err
	}
	failed := err != nil

	var e error
	switch action {
	case "":
		fmt.Printf("no action defined, nothing to do")
	case "detect":
		e = client.HandleDetect(&funcIdentifier, failed)
		if e != nil {
			e = fmt.Errorf("handleVerification failed on function indication: %w", e)
		}
	case "block":
		{
			e = client.HandleDetect(&funcIdentifier, failed)
			if e != nil {
				e = fmt.Errorf("handleVerification failed on function indication: %w", e)
				break
			}
			e = client.HandleBlock(&funcIdentifier, failed)
			if e != nil {
				e = fmt.Errorf("handleVerification failed on function block: %w", e)
				break
			}
		}
	}

	if failed && topicArn != "" {
		notification := clients.Notification{}
		err = client.FillNotificationDetails(&notification, funcIdentifier)
		if err != nil {
			return err
		}
		notification.Action = action
		msg, err := json.Marshal(notification)
		if err != nil {
			return err
		}
		e = client.Notify(string(msg), topicArn)
	}
	return e
}

func verifyImage(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context) error {
	imageURI, err := client.GetFuncImageURI(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to fetch function image URI for function: %s: %w", functionIdentifier, err)
	}
	annotations, err := o.AnnotationsMap()
	if err != nil {
		return err
	}

	hashAlgorithm, err := o.SignatureDigest.HashAlgorithm()
	if err != nil {
		return err
	}

	vc := v.VerifyCommand{
		RegistryOptions:              o.Registry,
		CheckClaims:                  o.CheckClaims,
		KeyRef:                       o.Key,
		CertRef:                      o.CertVerify.Cert,
		CertEmail:                    o.CertVerify.CertEmail,
		CertOidcIssuer:               o.CertVerify.CertOidcIssuer,
		CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        o.CertVerify.CertGithubWorkflowSha,
		CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
		CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
		CertChain:                    o.CertVerify.CertChain,
		EnforceSCT:                   o.CertVerify.EnforceSCT,
		Sk:                           o.SecurityKey.Use,
		Slot:                         o.SecurityKey.Slot,
		Output:                       o.Output,
		RekorURL:                     o.Rekor.URL,
		Attachment:                   o.Attachment,
		Annotations:                  annotations,
		HashAlgorithm:                hashAlgorithm,
		SignatureRef:                 o.SignatureRef,
		LocalImage:                   o.LocalImage,
	}

	if err = vc.Exec(ctx, []string{imageURI}); err != nil {
		return VerifyError{Err: fmt.Errorf("image verification error: %w", err)}
	}
	return nil
}

func verifyCode(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context) error {
	codePath, err := client.GetFuncCode(functionIdentifier)
	if err != nil {
		return fmt.Errorf("verify code: failed to fetch function code for function: %s: %w", functionIdentifier, err)
	}
	integrityCalculator := integrity.Sha256{}
	functionIdentity, err := integrityCalculator.GenerateIdentity(codePath)
	if err != nil {
		return fmt.Errorf("verify code: failed to generate function identity for function: %s: %w", functionIdentifier, err)
	}

	isKeyless := false
	if !o.SecurityKey.Use && o.Key == "" && o.BundlePath == "" && integrity.IsExperimentalEnv() {
		isKeyless = true
	}
	if err = downloadSignatureAndCertificate(client, functionIdentifier, functionIdentity, isKeyless); err != nil {
		return err
	}
	if err = verify.VerifyIdentity(functionIdentity, o, ctx, isKeyless); err != nil {
		return VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
	}
	return nil
}

func downloadSignatureAndCertificate(client clients.Client, functionIdentifier string, functionIdentity string, isKeyless bool) error {
	if err := client.Download(functionIdentity, "sig"); err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchKey" {
				return VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
			}
		} else {
			return fmt.Errorf("verify code: failed to get signed identity for function: %s, function idenity: %s: %w", functionIdentifier, functionIdentity, err)
		}
	}
	if isKeyless {
		if err := client.Download(functionIdentity, "crt.base64"); err != nil {
			if awsErr, ok := err.(awserr.Error); ok {
				if awsErr.Code() == "NoSuchKey" {
					return VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
				}
			} else {
				return fmt.Errorf("verify code: failed to get certificate for function: %s, function idenity: %s: %w", functionIdentifier, functionIdentity, err)
			}
		}
	}
	return nil
}
