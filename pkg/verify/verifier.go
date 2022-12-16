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
	"github.com/openclarity/functionclarity/cmd/function-clarity/cli/verify"
	"io"
	"os"
	"path/filepath"
	"strings"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/openclarity/functionclarity/pkg/clients"
	"github.com/openclarity/functionclarity/pkg/integrity"
	"github.com/openclarity/functionclarity/pkg/options"
	v "github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func Verify(client clients.Client, functionIdentifier string, o *options.VerifyOpts, ctx context.Context, action string,
	topicArn string, tagKeysFilter []string, filteredRegions []string, bucketPathToPublicKeys string) (string, bool, error) {

	if filteredRegions != nil && (len(filteredRegions) > 0) {
		funcInRegions := client.IsFuncInRegions(filteredRegions)
		if !funcInRegions {
			fmt.Printf("function: %s not in regions list: %s, skipping validation", functionIdentifier, filteredRegions)
			return "", false, nil
		}
	}

	if tagKeysFilter != nil && (len(tagKeysFilter) > 0) {
		funcContainsTag, err := client.FuncContainsTags(functionIdentifier, tagKeysFilter)
		if err != nil {
			return "", false, fmt.Errorf("check function tags: failed to check tags of function: %s: %w", functionIdentifier, err)
		}
		if !funcContainsTag {
			fmt.Printf("function: %s doesn't contain tag in the list: %s, skipping validation", functionIdentifier, tagKeysFilter)
			return "", false, nil
		}
	}
	packageType, err := client.ResolvePackageType(functionIdentifier)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve package type for function: %s: %w", functionIdentifier, err)
	}
	hash := ""
	switch packageType {
	case "Zip":
		hash, err = verifyCode(client, functionIdentifier, o, bucketPathToPublicKeys, ctx)
	case "Image":
		hash, err = verifyImage(client, functionIdentifier, o, bucketPathToPublicKeys, ctx)
	default:
		return "", false, fmt.Errorf("unsupported package type: %s for function: %s", packageType, functionIdentifier)
	}
	isVerified, err := HandleVerification(client, action, functionIdentifier, err, topicArn)
	return hash, isVerified, err
}

func HandleVerification(client clients.Client, action string, funcIdentifier string, err error, topicArn string) (bool, error) {
	if err != nil && !errors.Is(err, VerifyError{}) {
		return false, err
	}
	verificationFailed := err != nil

	fmt.Printf("verification result. failed: %t\n", verificationFailed)

	var e error
	switch action {
	case "":
		fmt.Printf("no action defined, nothing to do\n")
	case "detect":
		e = client.HandleDetect(&funcIdentifier, verificationFailed)
		if e != nil {
			e = fmt.Errorf("handleVerification failed on function indication: %w", e)
		}
	case "block":
		{
			e = client.HandleDetect(&funcIdentifier, verificationFailed)
			if e != nil {
				e = fmt.Errorf("handleVerification failed on function indication: %w", e)
				break
			}
			e = client.HandleBlock(&funcIdentifier, verificationFailed)
			if e != nil {
				e = fmt.Errorf("handleVerification failed on function block: %w", e)
				break
			}
		}
	}

	if verificationFailed && topicArn != "" {
		notification := clients.Notification{}
		err = client.FillNotificationDetails(&notification, funcIdentifier)
		if err != nil {
			return false, err
		}
		notification.Action = action
		msg, err := json.Marshal(notification)
		if err != nil {
			return false, err
		}
		e = client.Notify(string(msg), topicArn)
	}
	if e == nil && verificationFailed {
		return false, err
	}
	return verificationFailed, e
}

func verifyImage(client clients.Client, functionIdentifier string, o *options.VerifyOpts, bucketPathToPublicKeys string, ctx context.Context) (string, error) {
	funcHash, err := client.GetFuncImageURI(functionIdentifier)
	if err != nil {
		return "", fmt.Errorf("failed to fetch function hash for function: %s: %w", functionIdentifier, err)
	}
	imageURI, err := client.GetFuncImageURI(functionIdentifier)
	if err != nil {
		return funcHash, fmt.Errorf("failed to fetch function image URI for function: %s: %w", functionIdentifier, err)
	}

	annotations, err := o.AnnotationsMap()
	if err != nil {
		return funcHash, err
	}

	hashAlgorithm, err := o.SignatureDigest.HashAlgorithm()
	if err != nil {
		return funcHash, err
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
	if bucketPathToPublicKeys != "" {
		err = verifyMultipleKeys(client, bucketPathToPublicKeys, o, "", ctx, false, []string{imageURI}, nil, &vc)
		if err != nil {
			return funcHash, err
		}
	} else {
		if err = vc.Exec(ctx, []string{imageURI}); err != nil {
			return funcHash, VerifyError{Err: fmt.Errorf("image verification error: %w", err)}
		}
	}
	return funcHash, nil
}

func verifyCode(client clients.Client, functionIdentifier string, o *options.VerifyOpts, bucketPathToPublicKeys string, ctx context.Context) (string, error) {
	codePath, err := client.GetFuncCode(functionIdentifier)
	if err != nil {
		return "", fmt.Errorf("verify code: failed to fetch function code for function: %s: %w", functionIdentifier, err)
	}
	integrityCalculator := integrity.Sha256{}
	functionIdentity, err := integrityCalculator.GenerateIdentity(codePath)
	if err != nil {
		return "", fmt.Errorf("verify code: failed to generate function identity for function: %s: %w", functionIdentifier, err)
	}

	isKeyless := false
	if !o.SecurityKey.Use && o.Key == "" && o.BundlePath == "" && integrity.IsExperimentalEnv() {
		isKeyless = true
	}
	if err = downloadSignatureAndCertificate(client, functionIdentifier, functionIdentity, isKeyless); err != nil {
		return functionIdentity, err
	}
	if bucketPathToPublicKeys != "" {
		err = verifyMultipleKeys(client, bucketPathToPublicKeys, o, functionIdentity, ctx, isKeyless, nil, verify.VerifyIdentity, nil)
		if err != nil {
			return functionIdentity, err
		}
	} else {
		if err = verify.VerifyIdentity(functionIdentity, o, ctx, isKeyless); err != nil {
			return functionIdentity, VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
		}
	}

	return functionIdentity, nil
}

func verifyMultipleKeys(client clients.Client, bucketPathToPublicKeys string, o *options.VerifyOpts, functionIdentity string,
	ctx context.Context, isKeyless bool, images []string,
	codeValidationFunc func(identity string, o *options.VerifyOpts, ctx context.Context, isKeyless bool) error,
	verifyCommand *v.VerifyCommand) error {

	publicKeysFolder, err := client.DownloadBucketContent(bucketPathToPublicKeys)
	if err != nil {
		return fmt.Errorf("code verification error: %w", err)
	}
	err = filepath.Walk(publicKeysFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fmt.Printf("File Name: %s\n", info.Name())
			if codeValidationFunc != nil {
				o.Key = path
				err = codeValidationFunc(functionIdentity, o, ctx, isKeyless)
			} else {
				verifyCommand.KeyRef = path
				err = verifyCommand.Exec(ctx, images)
			}
			if err == nil {
				return io.EOF
			}
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
	}
	if err == nil {
		return VerifyError{Err: fmt.Errorf("couldn't find valid public key")}
	}
	return nil
}

func downloadSignatureAndCertificate(client clients.Client, functionIdentifier string, functionIdentity string, isKeyless bool) error {
	if err := client.DownloadSignature(functionIdentity, "sig"); err != nil {
		var nsk *s3types.NoSuchKey
		if errors.As(err, &nsk) || strings.Contains(err.Error(), "storage: object doesn't exist") {
			return VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
		}
		return fmt.Errorf("verify code: failed to get signed identity for function: %s, function idenity: %s: %w", functionIdentifier, functionIdentity, err)
	}
	if isKeyless {
		if err := client.DownloadSignature(functionIdentity, "crt.base64"); err != nil {
			var nsk *s3types.NoSuchKey
			if errors.As(err, &nsk) || strings.Contains(err.Error(), "storage: object doesn't exist") {
				return VerifyError{Err: fmt.Errorf("code verification error: %w", err)}
			}
			return fmt.Errorf("verify code: failed to get certificate for function: %s, function idenity: %s: %w", functionIdentifier, functionIdentity, err)
		}
	}
	return nil
}
