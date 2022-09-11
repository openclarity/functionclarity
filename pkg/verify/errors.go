package verify

import "fmt"

type VerifyError struct {
	Err error
}

func (e VerifyError) Error() string {
	return fmt.Sprintf("verification error: %w", e.Err)
}
