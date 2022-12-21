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

package clients

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	funcv1 "cloud.google.com/go/functions/apiv1"
	funcpb1 "cloud.google.com/go/functions/apiv1/functionspb"
	funcv2 "cloud.google.com/go/functions/apiv2"
	funcpb2 "cloud.google.com/go/functions/apiv2/functionspb"
	run "cloud.google.com/go/run/apiv2"
	"cloud.google.com/go/run/apiv2/runpb"
	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"github.com/openclarity/functionclarity/pkg/utils"
)

type GCPClient struct {
	bucket         string
	functionRegion string
}

func NewGCPClientInit(bucket string, location string, functionRegion string) *GCPClient {
	p := new(GCPClient)
	p.bucket = bucket
	p.functionRegion = functionRegion
	return p
}

func (p *GCPClient) Upload(signature string, identity string, isKeyless bool) error {
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage.NewClient: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	o := client.Bucket(p.bucket).Object(identity + ".sig")

	wc := o.NewWriter(ctx)
	if _, err = io.Copy(wc, strings.NewReader(signature)); err != nil {
		return fmt.Errorf("io.Copy: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("Writer.Close: %w", err)
	}
	fmt.Printf("Uploaded %v to: %v\n", identity+".sig", p.bucket)

	if isKeyless {
		certificatePath := utils.FunctionClarityHomeDir + identity + ".crt.base64"
		f, err := os.Open(certificatePath)
		if err != nil {
			return err
		}

		o := client.Bucket(p.bucket).Object(identity + ".crt.base64")

		wc := o.NewWriter(ctx)
		if _, err = io.Copy(wc, f); err != nil {
			return fmt.Errorf("io.Copy: %w", err)
		}
		if err := wc.Close(); err != nil {
			return fmt.Errorf("Writer.Close: %w", err)
		}
		fmt.Printf("Certificate %v, uploaded to: %v\n", identity+".crt.base64", p.bucket)
	}
	return nil
}

func (p *GCPClient) ResolvePackageType(funcIdentifier string) (string, error) {
	if strings.Contains(funcIdentifier, "services") {
		return "Image", nil
	}
	if strings.Contains(funcIdentifier, "functions") {
		return "Zip", nil
	}

	return "", fmt.Errorf("function identifier doesn't match to any known package type")

}

func (p *GCPClient) GetFuncCode(funcIdentifier string) (string, error) {
	url, err := getDownloadURLFuncGen1(funcIdentifier)
	if err != nil {
		url, err = getDownloadURLFuncGen2(funcIdentifier)
		if err != nil {
			return "", fmt.Errorf("failed to get function: %w", err)
		}
	}

	contentName := uuid.New().String()
	zipFileName := contentName + ".zip"

	if err := utils.DownloadFile(contentName+".zip", &url); err != nil {
		return "", err
	}
	if err := utils.ExtractZip(utils.FunctionClarityHomeDir+zipFileName, utils.FunctionClarityHomeDir+contentName); err != nil {
		return "", err
	}
	return utils.FunctionClarityHomeDir + contentName, nil
}

func getDownloadURLFuncGen1(funcIdentifier string) (string, error) {
	ctx := context.Background()
	client, err := funcv1.NewCloudFunctionsClient(ctx)
	if err != nil {
		return "", fmt.Errorf("cloud functions.NewClient: %w", err)
	}
	defer client.Close()

	downloadUrl, err := client.GenerateDownloadUrl(ctx, &funcpb1.GenerateDownloadUrlRequest{Name: funcIdentifier})
	if err != nil {
		return "", err
	}
	return downloadUrl.DownloadUrl, err
}

func getDownloadURLFuncGen2(funcIdentifier string) (string, error) {
	ctx := context.Background()
	client, err := funcv2.NewFunctionClient(ctx)
	if err != nil {
		return "", fmt.Errorf("cloud functions.NewClient: %w", err)
	}
	defer client.Close()

	downloadUrl, err := client.GenerateDownloadUrl(ctx, &funcpb2.GenerateDownloadUrlRequest{Name: funcIdentifier})
	if err != nil {
		return "", err
	}
	return downloadUrl.DownloadUrl, nil
}

func (p *GCPClient) GetFuncImageURI(funcIdentifier string) (string, error) {
	ctx := context.Background()
	client, err := run.NewServicesClient(ctx)
	if err != nil {
		return "", fmt.Errorf("cloud run.NewClient: %w", err)
	}
	defer client.Close()

	service, err := client.GetService(ctx, &runpb.GetServiceRequest{Name: funcIdentifier})
	if err != nil {
		return "", err
	}
	if len(service.Annotations) > 1 {
		return "", fmt.Errorf("there are more than one image connected to service: %v\n", funcIdentifier)
	}
	for _, a := range service.Annotations {
		return a, nil
	}
	return "", fmt.Errorf("there are no image connected to service: %v\n", funcIdentifier)
}

func (p *GCPClient) IsFuncInRegions(regions []string) bool {
	panic("not yet supported")
}

func (p *GCPClient) FuncContainsTags(funcIdentifier string, tagKes []string) (bool, error) {
	panic("not yet supported")
}

func (p *GCPClient) DownloadSignature(fileName string, outputType string, bucketPathToSignatures string) error {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage.NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	outputFile := utils.FunctionClarityHomeDir + fileName + "." + outputType
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("os.Create: %v", err)
	}

	objectName := fileName + "." + outputType
	rc, err := client.Bucket(p.bucket).Object(objectName).NewReader(ctx)
	if err != nil {
		return fmt.Errorf("Object(%q).NewReader: %v", objectName, err)
	}
	defer rc.Close()

	if _, err := io.Copy(f, rc); err != nil {
		return fmt.Errorf("io.Copy: %v", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("f.Close: %v", err)
	}
	fmt.Printf("Downloaded %v to: %v\n", objectName, outputFile)
	return nil
}

func (p *GCPClient) HandleBlock(funcIdentifier *string, failed bool) error {
	panic("not yet supported")
}

func (p *GCPClient) HandleDetect(funcIdentifier *string, failed bool) error {
	panic("not yet supported")
}

func (p *GCPClient) Notify(msg string, snsArn string) error {
	panic("not yet supported")
}

func (p *GCPClient) FillNotificationDetails(notification *Notification, functionIdentifier string) error {
	panic("not yet supported")
}

func (o *GCPClient) DownloadBucketContent(bucketPath string) (string, error) {
	panic("not yet supported")
}

func (o *GCPClient) DownloadFile(fileName string, path string, bucketName string) error {
	panic("not yet supported")
}

func (o *GCPClient) GetFuncHash(funcIdentifier string) (string, error) {
	panic("not yet supported")
}
