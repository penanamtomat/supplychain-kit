// Package joern wraps the joern CLI to produce a Code Property Graph (CPG)
// export. The export path is surfaced via Result.Artifacts so the
// reachability engine can consume it without re-parsing source.
//
// Joern itself produces no findings in this adapter — its sole responsibility
// is generating a CPG. SAST findings are produced by Semgrep; Joern's role is
// to power the reachability engine.
package joern

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

const ArtifactCPGPath = "cpg_path"

// Adapter wraps the joern-parse + joern-export CLI pipeline.
type Adapter struct {
	parseBinary  string
	exportBinary string
}

// New returns a default Joern adapter targeting the binaries on PATH.
func New() *Adapter {
	return &Adapter{parseBinary: "joern-parse", exportBinary: "joern-export"}
}

func (a *Adapter) Name() string                  { return "joern" }
func (a *Adapter) Source() models.FindingSource { return models.SourceJoern }

func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source(), Artifacts: map[string]string{}}

	cpgBin := filepath.Join(req.CheckoutDir, ".aspm", "cpg.bin")
	cpgExport := filepath.Join(req.CheckoutDir, ".aspm", "cpg-export")
	if err := os.MkdirAll(filepath.Dir(cpgBin), 0o755); err != nil {
		return out, err
	}

	parse := exec.CommandContext(ctx, a.parseBinary, req.CheckoutDir, "--output", cpgBin)
	parse.Stderr = os.Stderr
	if err := parse.Run(); err != nil {
		return out, fmt.Errorf("joern-parse: %w", err)
	}

	export := exec.CommandContext(ctx, a.exportBinary, cpgBin, "--repr", "all", "--format", "graphson", "--out", cpgExport)
	export.Stderr = os.Stderr
	if err := export.Run(); err != nil {
		return out, fmt.Errorf("joern-export: %w", err)
	}

	out.Artifacts[ArtifactCPGPath] = cpgExport
	return out, nil
}
