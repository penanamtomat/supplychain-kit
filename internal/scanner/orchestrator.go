package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Orchestrator runs the full scan pipeline against a repository:
//
//  1. clone the repo into a temp workspace
//  2. fan out to every registered scanner concurrently
//  3. let downstream callers (correlation, reachability, scoring) take over
//
// Returns the per-scanner results, the artifact map (e.g. SBOM path, CPG path),
// and the cleanup function the caller is expected to defer.
func (r *Registry) RunPipeline(ctx context.Context, asset *models.Asset, ref string) ([]ScannedResult, map[string]string, func(), error) {
	workdir, err := os.MkdirTemp("", "aspm-scan-*")
	if err != nil {
		return nil, nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(workdir) }

	checkout := filepath.Join(workdir, "src")
	if err := gitClone(ctx, asset.RepoURL, ref, checkout); err != nil {
		cleanup()
		return nil, nil, nil, err
	}

	req := Request{
		ScanRunID:   uuid.NewString(),
		AssetID:     asset.ID,
		CheckoutDir: checkout,
	}

	results := r.RunAll(ctx, req)

	// Aggregate artifacts so downstream stages can reference them by key.
	artifacts := map[string]string{}
	for _, res := range results {
		for k, v := range res.Result.Artifacts {
			artifacts[k] = v
		}
	}
	return results, artifacts, cleanup, nil
}

func gitClone(ctx context.Context, url, ref, dest string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", url, dest)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	if ref != "" && ref != "HEAD" {
		fetch := exec.CommandContext(ctx, "git", "-C", dest, "fetch", "origin", ref)
		fetch.Stderr = os.Stderr
		_ = fetch.Run() // best-effort; the shallow clone may already include it
		checkout := exec.CommandContext(ctx, "git", "-C", dest, "checkout", ref)
		checkout.Stderr = os.Stderr
		_ = checkout.Run()
	}
	return nil
}
