package scanner

import (
	"fmt"
	"os/exec"
)

// ErrBinaryNotFound is returned by adapters when the underlying CLI tool is
// not present on PATH. Callers (e.g. the registry) treat this as a skip, not
// a hard failure, so a missing tool never aborts the whole scan run.
type ErrBinaryNotFound struct {
	Binary string
}

func (e ErrBinaryNotFound) Error() string {
	return fmt.Sprintf("%q not found on PATH — install it or see scripts/install-tools.sh", e.Binary)
}

// CheckBinary returns ErrBinaryNotFound if name cannot be resolved on PATH.
func CheckBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return ErrBinaryNotFound{Binary: name}
	}
	return nil
}
