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
	"testing"
)

func TestGenerateIdentityIdempotence(t *testing.T) {
	const pathToSourceCode = "../../test_utils/source_for_testing/code_for_testing/"
	const pathToIdenticalSourceCode = "../../test_utils/identical_source_for_testing/code_for_testing/"

	integrityCalculator := Sha256{}
	generateIdentity, err := integrityCalculator.GenerateIdentity(pathToSourceCode)
	if err != nil {
		t.Fatalf("Failed to generate code identity for code in: %s", pathToSourceCode)
	}

	identicalGenerateIdentity, err := integrityCalculator.GenerateIdentity(pathToIdenticalSourceCode)
	if err != nil {
		t.Fatalf("Failed to generate code identity for code in: %s", pathToIdenticalSourceCode)
	}

	if generateIdentity != identicalGenerateIdentity {
		t.Fatalf("Error. The generated identities aren't consistent")
	}
}

func TestGenerateIdentityUniqueness(t *testing.T) {
	const pathToSourceCode = "../../test_utils/source_for_testing/code_for_testing/"
	const pathToChangedSourceCode = "../../test_utils/changed_code_for_testing/"

	integrityCalculator := Sha256{}
	generateIdentity, err := integrityCalculator.GenerateIdentity(pathToSourceCode)
	if err != nil {
		t.Fatalf("Failed to generate code identity for code in: %s", pathToSourceCode)
	}

	identicalGenerateIdentity, err := integrityCalculator.GenerateIdentity(pathToChangedSourceCode)
	if err != nil {
		t.Fatalf("Failed to generate code identity for code in: %s", pathToChangedSourceCode)
	}

	if generateIdentity == identicalGenerateIdentity {
		t.Fatalf("Error. The generated identities should be different")
	}
}
