package scanner_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

// fakeScanner is a controllable Scanner implementation for tests.
type fakeScanner struct {
	name   string
	result scanner.Result
	err    error
	called *bool
}

func (f *fakeScanner) Name() string                  { return f.name }
func (f *fakeScanner) Source() models.FindingSource { return models.FindingSource(f.name) }
func (f *fakeScanner) Scan(_ context.Context, _ scanner.Request) (scanner.Result, error) {
	if f.called != nil {
		*f.called = true
	}
	return f.result, f.err
}

// TestTwoPhase_SyftFailSkipsGrype verifies that when syft fails (no SBOM
// produced), grype is not executed in phase 2.
func TestTwoPhase_SyftFailSkipsGrype(t *testing.T) {
	grypeCalled := false

	fakeSyft := &fakeScanner{
		name: "syft",
		err:  errors.New("syft: binary not found"),
	}
	fakeGrype := &fakeScanner{
		name:   "grype",
		called: &grypeCalled,
	}

	reg := scanner.NewRegistry(fakeSyft, fakeGrype)
	results, _ := reg.RunLocal(context.Background(), &models.Asset{ID: "test"}, t.TempDir())

	if grypeCalled {
		t.Fatal("grype should not have been called when syft failed to produce an SBOM")
	}

	// syft result should still appear (with its error surfaced)
	syftFound := false
	for _, r := range results {
		if r.Scanner == "syft" {
			syftFound = true
			if r.Err == nil {
				t.Error("expected syft result to carry an error")
			}
		}
	}
	if !syftFound {
		t.Error("expected syft result in output")
	}
}

// TestTwoPhase_SCAEndToEnd exercises the full syft→grype pipeline using fake
// adapters that return canned findings identical to the testdata fixtures.
// This verifies that the SBOM path flows correctly from syft to grype.
func TestTwoPhase_SCAEndToEnd(t *testing.T) {
	// Write a minimal SBOM fixture into a temp directory so fakeSyft can
	// surface its path as an artifact (mirroring what the real syft does).
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, ".aspm", "sbom.cdx.json")
	if err := os.MkdirAll(filepath.Dir(sbomPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeSyft := &fakeScanner{
		name: "syft",
		result: scanner.Result{
			Source:    models.SourceSyft,
			Artifacts: map[string]string{scanner.ArtifactSBOMPath: sbomPath},
		},
	}

	var receivedSBOMPath string
	fakeGrype := &fakeGrypeCapture{sbomCapture: &receivedSBOMPath}

	reg := scanner.NewRegistry(fakeSyft, fakeGrype)
	results, artifacts := reg.RunLocal(context.Background(), &models.Asset{ID: "asset-1"}, dir)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if artifacts[scanner.ArtifactSBOMPath] != sbomPath {
		t.Errorf("expected SBOM path %s in artifacts, got %q", sbomPath, artifacts[scanner.ArtifactSBOMPath])
	}
	if receivedSBOMPath != sbomPath {
		t.Errorf("grype did not receive SBOM path: got %q, want %q", receivedSBOMPath, sbomPath)
	}
}

// fakeGrypeCapture captures the SBOMPath from the Request passed to it.
type fakeGrypeCapture struct {
	sbomCapture *string
}

func (f *fakeGrypeCapture) Name() string                  { return "grype" }
func (f *fakeGrypeCapture) Source() models.FindingSource { return models.SourceGrype }
func (f *fakeGrypeCapture) Scan(_ context.Context, req scanner.Request) (scanner.Result, error) {
	*f.sbomCapture = req.SBOMPath
	return scanner.Result{Source: models.SourceGrype}, nil
}

// TestRegistry_ModeSCA verifies that a registry built for SCA mode (syft + grype
// only) produces results from exactly those two scanners and nothing else.
func TestRegistry_ModeSCA(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, ".aspm", "sbom.cdx.json")
	if err := os.MkdirAll(filepath.Dir(sbomPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeSyft := &fakeScanner{
		name:   "syft",
		result: scanner.Result{Source: models.SourceSyft, Artifacts: map[string]string{scanner.ArtifactSBOMPath: sbomPath}},
	}
	fakeGrype := &fakeScanner{name: "grype", result: scanner.Result{Source: models.SourceGrype}}

	// SCA mode: only syft + grype, no semgrep/gitleaks/joern
	reg := scanner.NewRegistry(fakeSyft, fakeGrype)
	results, _ := reg.RunLocal(context.Background(), &models.Asset{ID: "asset-sca"}, dir)

	if len(results) != 2 {
		t.Fatalf("SCA mode: expected 2 scanner results, got %d", len(results))
	}
	names := map[string]bool{}
	for _, r := range results {
		names[r.Scanner] = true
	}
	if !names["syft"] || !names["grype"] {
		t.Errorf("SCA mode: expected syft+grype results, got %v", names)
	}
}
