package scanner_test

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

func TestCheckBinary_NotFound(t *testing.T) {
	err := scanner.CheckBinary("__tool_that_does_not_exist__")
	if err == nil {
		t.Fatal("expected ErrBinaryNotFound, got nil")
	}
	if _, ok := err.(scanner.ErrBinaryNotFound); !ok {
		t.Fatalf("expected ErrBinaryNotFound, got %T: %v", err, err)
	}
}

func TestCheckBinary_Found(t *testing.T) {
	// "go" is always present in the test environment.
	if err := scanner.CheckBinary("go"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}
