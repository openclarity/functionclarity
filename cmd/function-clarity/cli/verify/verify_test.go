package verify

import (
	"github.com/openclarity/function-clarity/pkg/integrity"
	"testing"
)

func TestVerifyIdentitySuccess(t *testing.T) {
	const pathToTestingPair = "../../../../test_utils/tasting_keys/"
	const identity = "739356fc846067a7aa2e80fb6c3bf4e7f482ad80870cdf225ece9582576f3b2c"
	const si = "MEQCIEvNqHFMor+DAlHVexDzrW4o81xGmIuznepLyMLzYw2mAiB6FdUT85eA6ZDMy6GByiVuQXDH03qCvAsGMxse5t0vxg=="

	err := VerifyIdentity(pathToTestingPair+"cosign.pub", si, identity)
	key, _ := integrity.ReadFile(pathToTestingPair + "cosign.pub")
	if err != nil {
		t.Fatalf("Error, signature: %s cannot be varified by public key: %s, error: %v", si, key, err)
	}
}

func TestVerifyIdentityFailureOnWrongIdentity(t *testing.T) {
	const pathToTestingPair = "../../../../test_utils/tasting_keys/"
	const identity_wrong = "4e725b9b14ccdf2149608747152c04b1ea6717049276302ffdfd30dacee99436"
	const si = "MEQCIEvNqHFMor+DAlHVexDzrW4o81xGmIuznepLyMLzYw2mAiB6FdUT85eA6ZDMy6GByiVuQXDH03qCvAsGMxse5t0vxg=="

	err := VerifyIdentity(pathToTestingPair+"cosign.pub", si, identity_wrong)
	key, _ := integrity.ReadFile(pathToTestingPair + "cosign.pub")
	if err == nil {
		t.Fatalf("Error, signature: %s varified by public key: %s, despite it should fail verification because of wrong identity", si, key)
	}
}

func TestVerifyIdentityFailureOnWrongPublicKey(t *testing.T) {
	const identity = "739356fc846067a7aa2e80fb6c3bf4e7f482ad80870cdf225ece9582576f3b2c"
	const pathToTestingPair = "../../../../test_utils/tasting_keys/"
	const si = "MEQCIEvNqHFMor+DAlHVexDzrW4o81xGmIuznepLyMLzYw2mAiB6FdUT85eA6ZDMy6GByiVuQXDH03qCvAsGMxse5t0vxg=="

	err := VerifyIdentity(pathToTestingPair+"cosign_wrong.pub", si, identity)
	key, _ := integrity.ReadFile(pathToTestingPair + "cosign_wrong.pub")
	if err == nil {
		t.Fatalf("Error, signature: %s varified by public key: %s, despite it should fail verification because of wrong public key", si, key)
	}
}
