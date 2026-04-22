package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Mode controls which scanner groups are activated.
type Mode string

const (
	ModeSCA  Mode = "sca"  // syft + grype only
	ModeSAST Mode = "sast" // semgrep + gitleaks only
	ModeAll  Mode = "all"  // all scanners (default)
)

// RunPipeline clones the repo and runs the full two-phase scan pipeline:
//
//  Phase 1 — syft (SBOM generation, must complete before grype)
//  Phase 2 — grype + remaining scanners concurrently
//
// Returns per-scanner results, aggregated artifacts, cleanup func, and error.
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

	results, artifacts := r.runTwoPhase(ctx, req)
	return results, artifacts, cleanup, nil
}

// RunLocal runs the two-phase scan pipeline against a pre-existing local directory
// (no git clone). The caller is responsible for the directory's lifecycle.
func (r *Registry) RunLocal(ctx context.Context, asset *models.Asset, dir string) ([]ScannedResult, map[string]string) {
	req := Request{
		ScanRunID:   "local",
		AssetID:     asset.ID,
		CheckoutDir: dir,
	}
	return r.runTwoPhase(ctx, req)
}

// runTwoPhase executes the scan in dependency order:
//
//  Phase 1: run syft alone and wait — its SBOM output is needed by grype.
//  Phase 2: run grype (with SBOM path injected) + all other scanners concurrently.
//
// Any scanner not registered is silently skipped.
func (r *Registry) runTwoPhase(ctx context.Context, req Request) ([]ScannedResult, map[string]string) {
	artifacts := map[string]string{}
	var results []ScannedResult

	// Phase 1: syft (serial — must finish before grype)
	var phase2 []Scanner
	for _, s := range r.scanners {
		if s.Name() == "syft" {
			log.Info().Str("scanner", "syft").Msg("phase 1: generating SBOM")
			result, err := s.Scan(ctx, req)
			if err != nil {
				if _, notFound := err.(ErrBinaryNotFound); notFound {
					log.Warn().Str("scanner", s.Name()).Msg(err.Error())
				} else {
					log.Warn().Err(err).Str("scanner", s.Name()).Msg("scanner failed")
				}
			}
			for k, v := range result.Artifacts {
				artifacts[k] = v
			}
			results = append(results, ScannedResult{Scanner: s.Name(), Result: result, Err: err})
		} else {
			phase2 = append(phase2, s)
		}
	}

	// Inject SBOM path into request so grype finds it without guessing.
	if sbomPath, ok := artifacts[ArtifactSBOMPath]; ok {
		req.SBOMPath = sbomPath
	} else {
		// syft did not produce an SBOM — remove grype from phase 2 so it
		// doesn't run against a non-existent file.
		filtered := phase2[:0]
		for _, s := range phase2 {
			if s.Name() == "grype" {
				log.Warn().Msg("syft did not produce SBOM — skipping grype")
			} else {
				filtered = append(filtered, s)
			}
		}
		phase2 = filtered
	}

	// Phase 2: grype + semgrep + gitleaks + joern — all concurrent.
	if len(phase2) > 0 {
		log.Info().Msg("phase 2: running remaining scanners concurrently")
		phase2Reg := &Registry{scanners: phase2}
		phase2Results := phase2Reg.RunAll(ctx, req)
		for _, r := range phase2Results {
			for k, v := range r.Result.Artifacts {
				artifacts[k] = v
			}
		}
		results = append(results, phase2Results...)
	}

	return results, artifacts
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
		_ = fetch.Run()
		checkout := exec.CommandContext(ctx, "git", "-C", dest, "checkout", ref)
		checkout.Stderr = os.Stderr
		_ = checkout.Run()
	}
	return nil
}
