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
	"cloud.google.com/go/storage"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

type GCPProperties struct {
	bucket         string
	location       string
	functionRegion string
}

func NewGCPPropertiesInit(bucket string, location string, functionRegion string) *GCPProperties {
	p := new(GCPProperties)
	p.bucket = bucket
	p.location = location
	p.functionRegion = functionRegion
	return p
}

func (p *GCPProperties) Upload(signature string, identity string, isKeyless bool) error {
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
	fmt.Printf("Uploaded %v to: %v\n", identity+".sig\n", p.bucket)
	return nil
}

func (p *GCPProperties) ResolvePackageType(funcIdentifier string) (string, error) {
	panic("not yet supported")
}

func (p *GCPProperties) GetFuncCode(funcIdentifier string) (string, error) {
	panic("not yet supported")
}

func (p *GCPProperties) GetFuncImageURI(funcIdentifier string) (string, error) {
	panic("not yet supported")
}

func (p *GCPProperties) IsFuncInRegions(regions []string) bool {
	panic("not yet supported")
}

func (p *GCPProperties) FuncContainsTags(funcIdentifier string, tagKes []string) (bool, error) {
	panic("not yet supported")
}

func (p *GCPProperties) Download(fileName string, outputType string) error {
	panic("not yet supported")
}

func (p *GCPProperties) HandleBlock(funcIdentifier *string, failed bool) error {
	panic("not yet supported")
}

func (p *GCPProperties) HandleDetect(funcIdentifier *string, failed bool) error {
	panic("not yet supported")
}

func (p *GCPProperties) Notify(msg string, snsArn string) error {
	panic("not yet supported")
}

func (p *GCPProperties) FillNotificationDetails(notification *Notification, functionIdentifier string) error {
	panic("not yet supported")
}
