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

package main

import (
	"github.com/openclarity/functionclarity/cmd/function-clarity/cli"
	"github.com/openclarity/functionclarity/pkg/utils"
	"log"
	"os"
)

func main() {
	if err := os.MkdirAll(utils.FunctionClarityHomeDir, os.ModePerm); err != nil {
		log.Fatal("Can't create home dir", err)
	}
	cli.New().Execute() //nolint:errcheck
}
