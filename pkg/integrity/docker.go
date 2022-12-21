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

package integrity

import (
	"encoding/base64"
	"encoding/json"
	"github.com/openclarity/functionclarity/pkg/utils"
	"os"
	"strings"

	"github.com/openclarity/functionclarity/pkg/clients"
)

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerAuth struct {
	Auths map[string]Auth `json:"auths"`
}

func InitDocker(awsClient *clients.AwsClient) error {
	ecrToken, err := awsClient.GetEcrToken()
	if err != nil {
		return err
	}
	dockerAuth := DockerAuth{Auths: map[string]Auth{}}
	for _, ad := range ecrToken.AuthorizationData {
		usernamePassword, err := base64.StdEncoding.DecodeString(*ad.AuthorizationToken)
		if err != nil {
			return err
		}
		split := strings.Split(string(usernamePassword), ":")
		dockerAuth.Auths[*ad.ProxyEndpoint] = Auth{
			Username: split[0],
			Password: split[1],
		}
	}
	if err != nil {
		return err
	}

	homeDir := utils.HomeDir

	dockerConfigDir := homeDir + "/.docker"
	err = os.MkdirAll(dockerConfigDir, 0700)
	if err != nil {
		return err
	}

	dockerConfigJson, err := json.Marshal(dockerAuth)
	if err != nil {
		return err
	}

	err = os.WriteFile(dockerConfigDir+"/config.json", dockerConfigJson, 0600)
	if err != nil {
		return err
	}
	return nil
}
