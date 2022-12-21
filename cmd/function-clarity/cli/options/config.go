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
	"fmt"
	"github.com/openclarity/functionclarity/pkg/utils"
	"github.com/spf13/viper"
)

var Config string = ""

func CobraInit() {
	if Config != "" {
		viper.SetConfigFile(Config)
		viper.SetConfigType("yaml")
	} else {
		home := utils.FunctionClarityHomeDir
		viper.AddConfigPath(home)
		viper.SetConfigName(".fc")
		viper.SetConfigType("yaml")
	}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error loading config file: %s\n", err)
	}
	if viper.ConfigFileUsed() != "" {
		fmt.Printf("using config file: %s\n", viper.ConfigFileUsed())
	}
}
