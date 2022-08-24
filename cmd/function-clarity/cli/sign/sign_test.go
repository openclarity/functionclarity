package sign

import (
	"github.com/openclarity/function-clarity/cmd/function-clarity/cli/verify"
	"github.com/openclarity/function-clarity/pkg/integrity"
	"os"
	"testing"
)

func TestSignIdentitySuccess(t *testing.T) {
	const identity = "739356fc846067a7aa2e80fb6c3bf4e7f482ad80870cdf225ece9582576f3b2c"
	const pathToTestingPair = "../../../../test_utils/tasting_keys/"

	funcDefer, err := mockStdin(t, "pass")
	if err != nil {
		t.Fatal(err)
	}
	defer funcDefer()

	si, err := SignIdentity(pathToTestingPair+"cosign.key", identity)
	if err != nil {
		t.Fatalf("Error signing idenitity: %v", err)
	}

	err = verify.VerifyIdentity(pathToTestingPair+"cosign.pub", si, identity)
	key, err := integrity.ReadFile(pathToTestingPair + "cosign.pub")
	if err != nil {
		t.Fatalf("Error, signature: %s cannot be varified by public key: %s, error: %v", si, key, err)
	}
}

func mockStdin(t *testing.T, dummyInput string) (funcDefer func(), err error) {
	t.Helper()

	tmpfile, err := os.CreateTemp(t.TempDir(), t.Name())

	if err != nil {
		return nil, err
	}

	content := []byte(dummyInput)

	if _, err := tmpfile.Write(content); err != nil {
		return nil, err
	}

	if _, err := tmpfile.Seek(0, 0); err != nil {
		return nil, err
	}

	oldOsStdin := os.Stdin
	os.Stdin = tmpfile

	return func() {
		os.Stdin = oldOsStdin
		os.Remove(tmpfile.Name())
	}, nil
}
