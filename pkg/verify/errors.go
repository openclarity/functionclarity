package verify

import (
	"fmt"
)

type VerifyError struct {
	Err error
}

func (e VerifyError) Error() string {
	return fmt.Sprintf("verification error: %v", e.Err)
}
func (m VerifyError) Is(target error) bool {
	return target == VerifyError{}
}
