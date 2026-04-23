package deptrack_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/deptrack"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// TestSyncE2E verifies that the sync workflow (syft → upload to Dependency-Track)
// works end-to-end when syft is installed. The DT server is mocked via httptest.
func TestSyncE2E(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed — skipping sync e2e test")
	}

	// Mock Dependency-Track server.
	var uploadedBOM string
	callLog := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callLog = append(callLog, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "project"):
			// EnsureProject: return existing project
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{"uuid": "sync-proj-uuid", "name": "test-sync", "version": "latest"},
			})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "bom"):
			// UploadBOM
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			uploadedBOM = payload["bom"]
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Run syft against the repo root to generate an SBOM.
	repoRoot, _ := filepath.Abs("../..")
	syftScanner := syftadapter.New()
	reg := scanner.NewRegistry(syftScanner)
	asset := &models.Asset{ID: "local", Name: repoRoot, Environment: models.EnvDev, Tier: 2}
	results, _ := reg.RunLocal(context.Background(), asset, repoRoot)

	var sbomRaw []byte
	for _, r := range results {
		if p, ok := r.Result.Artifacts[scanner.ArtifactSBOMPath]; ok {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read sbom: %v", err)
			}
			sbomRaw = data
			break
		}
	}
	if sbomRaw == nil {
		t.Fatal("syft did not produce an SBOM — check syft output")
	}

	// Upload to mocked Dependency-Track.
	client := deptrack.New(srv.URL, "test-key")
	uuid, err := client.EnsureProject(context.Background(), "test-sync", "latest")
	if err != nil {
		t.Fatalf("EnsureProject() error = %v", err)
	}
	if uuid != "sync-proj-uuid" {
		t.Errorf("uuid = %q, want sync-proj-uuid", uuid)
	}

	if err := client.UploadBOM(context.Background(), uuid, sbomRaw); err != nil {
		t.Fatalf("UploadBOM() error = %v", err)
	}

	// Verify BOM was received (base64-encoded, non-empty).
	if uploadedBOM == "" {
		t.Error("DT server received empty BOM payload")
	}

	t.Logf("sync e2e OK — sbom size=%d bytes, dt calls=%v", len(sbomRaw), callLog)
}
