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

type Notification struct {
	AccountId          string
	FunctionName       string
	FunctionIdentifier string
	Action             string
	Region             string
}

const ConfigEnvVariableName = "CONFIGURATION"

type Client interface {
	ResolvePackageType(funcIdentifier string) (string, error)
	GetFuncCode(funcIdentifier string) (string, error)
	GetFuncImageURI(funcIdentifier string) (string, error)
	GetFuncHash(funcIdentifier string) (string, error)
	IsFuncInRegions(regions []string) bool
	FuncContainsTags(funcIdentifier string, tagKes []string) (bool, error)
	Upload(signature string, identity string, isKeyless bool) error
	DownloadSignature(fileName string, outputType string, bucketPathToSignatures string) error
	HandleBlock(funcIdentifier *string, failed bool) error
	HandleDetect(funcIdentifier *string, failed bool) error
	Notify(msg string, snsArn string) error
	FillNotificationDetails(notification *Notification, functionIdentifier string) error
	DownloadBucketContent(bucketPath string) (string, error)
	DownloadFile(fileName string, folderToSave string, bucketName string) error
}
