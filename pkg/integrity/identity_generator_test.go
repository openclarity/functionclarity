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
		t.Fatalf("Error. The generated identities should be diffrent")
	}
}
