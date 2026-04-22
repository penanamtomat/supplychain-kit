package joern_test

import (
	"context"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/joern"
)

func TestAdapter_BinaryNotFound(t *testing.T) {
	a := joern.NewWithBinary("__joern_parse_missing__", "joern-export")
	_, err := a.Scan(context.Background(), scanner.Request{CheckoutDir: t.TempDir()})
	if _, ok := err.(scanner.ErrBinaryNotFound); !ok {
		t.Fatalf("expected ErrBinaryNotFound, got %T: %v", err, err)
	}
}
