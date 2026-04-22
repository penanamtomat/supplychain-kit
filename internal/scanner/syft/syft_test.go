package syft_test

import (
	"context"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
)

func TestAdapter_BinaryNotFound(t *testing.T) {
	a := syftadapter.NewWithBinary("__syft_missing__")
	_, err := a.Scan(context.Background(), scanner.Request{CheckoutDir: t.TempDir()})
	if _, ok := err.(scanner.ErrBinaryNotFound); !ok {
		t.Fatalf("expected ErrBinaryNotFound, got %T: %v", err, err)
	}
}

func TestLoadSBOM(t *testing.T) {
	sb, err := syftadapter.LoadSBOM("testdata/sbom.cdx.json", "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if sb.AssetID != "asset-1" {
		t.Errorf("unexpected asset_id: %s", sb.AssetID)
	}
	if sb.SpecVer != "1.5" {
		t.Errorf("expected spec version 1.5, got %s", sb.SpecVer)
	}
	if len(sb.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(sb.Components))
	}
	if sb.Components[0].Name != "github.com/gin-gonic/gin" {
		t.Errorf("unexpected component name: %s", sb.Components[0].Name)
	}
	if sb.ID == "" {
		t.Error("SBOM ID must not be empty")
	}
}
