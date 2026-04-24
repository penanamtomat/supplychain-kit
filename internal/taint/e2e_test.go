//go:build integration

package taint_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
	"github.com/penanamtomat/supplychain-kit/internal/taint"
)

// skipUnlessJoern skips the test if joern-parse or joern-export are not on PATH.
func skipUnlessJoern(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"joern-parse", "joern-export", "grype", "syft"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH, skipping E2E test", bin)
		}
	}
}

// createVulnerableApp writes a Go app that directly uses vulnerable functions.
func createVulnerableApp(t *testing.T, dir string) {
	t.Helper()

	mainGo := `package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

func sshHandler(c *gin.Context) {
	host := c.Query("host")
	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer client.Close()
	c.JSON(200, gin.H{"connected": host})
}

func main() {
	r := gin.Default()
	r.GET("/ssh", sshHandler)
	r.Run(":8080")
}
`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatal(err)
	}

	// go mod init + get vulnerable deps
	run := func(args ...string) {
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("go %v: %v", args, err)
		}
	}
	run("mod", "init", "e2e-test-app")
	run("get", "github.com/gin-gonic/gin@v1.9.1")
	run("get", "golang.org/x/crypto@v0.17.0")
	run("mod", "tidy")
}

// generateCPG runs joern-parse + joern-export on the repo.
func generateCPG(t *testing.T, repoDir string) string {
	t.Helper()

	cpgBin := filepath.Join(repoDir, ".aspm", "cpg.bin")
	cpgExport := filepath.Join(repoDir, ".aspm", "cpg-export")
	if err := os.MkdirAll(filepath.Dir(cpgBin), 0o755); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(cpgExport)

	parse := exec.Command("joern-parse", repoDir, "--output", cpgBin)
	parse.Stderr = os.Stderr
	if err := parse.Run(); err != nil {
		t.Fatalf("joern-parse: %v", err)
	}

	export := exec.Command("joern-export", cpgBin, "--repr", "all", "--format", "graphson", "--out", cpgExport)
	export.Stderr = os.Stderr
	if err := export.Run(); err != nil {
		t.Fatalf("joern-export: %v", err)
	}

	return cpgExport
}

func TestE2E_TaintAnalysis_ConfirmedExploitable(t *testing.T) {
	skipUnlessJoern(t)

	dir := t.TempDir()
	createVulnerableApp(t, dir)
	cpgPath := generateCPG(t, dir)

	cpg, err := reachability.LoadCPG(cpgPath)
	if err != nil {
		t.Fatalf("LoadCPG: %v", err)
	}
	if len(cpg.Vertices) == 0 {
		t.Fatal("CPG has no vertices")
	}

	engine := taint.NewEngine(cpg)

	// Simulate SCA findings from grype for golang.org/x/crypto (has known CVEs)
	findings := []*models.Finding{
		{
			RuleID:      "CVE-2024-45337",
			Package:     "golang.org/x/crypto",
			Severity:    models.SeverityCritical,
			Reachability: models.ReachUnknown,
		},
		{
			RuleID:      "CVE-2025-22869",
			Package:     "golang.org/x/crypto",
			Severity:    models.SeverityHigh,
			Reachability: models.ReachUnknown,
		},
		// This package is not directly used — should NOT be confirmed exploitable
		{
			RuleID:      "CVE-2023-44487",
			Package:     "golang.org/x/net",
			Severity:    models.SeverityHigh,
			Reachability: models.ReachUnknown,
		},
	}

	engine.Analyze(findings)

	// golang.org/x/crypto findings should be confirmed_exploitable
	// because ssh.InsecureIgnoreHostKey is called from HTTP handler
	cryptoExploitable := 0
	for _, f := range findings {
		if f.Package == "golang.org/x/crypto" {
			if f.Reachability == models.ReachConfirmedExploit {
				cryptoExploitable++
				if f.Confidence <= 0 {
					t.Errorf("CVE %s: expected confidence > 0, got %f", f.RuleID, f.Confidence)
				}
				if len(f.Path) == 0 {
					t.Errorf("CVE %s: expected non-empty taint path", f.RuleID)
				}
			} else {
				t.Errorf("CVE %s: expected confirmed_exploitable, got %s", f.RuleID, f.Reachability)
			}
		}
	}
	if cryptoExploitable != 2 {
		t.Errorf("Expected 2 crypto findings confirmed exploitable, got %d", cryptoExploitable)
	}

	// golang.org/x/net should NOT be confirmed exploitable
	for _, f := range findings {
		if f.Package == "golang.org/x/net" {
			if f.Reachability == models.ReachConfirmedExploit {
				t.Errorf("CVE %s: x/net should NOT be confirmed exploitable (not directly used)", f.RuleID)
			}
		}
	}
}

func TestE2E_LoadCPG_RealJoernExport(t *testing.T) {
	skipUnlessJoern(t)

	dir := t.TempDir()
	createVulnerableApp(t, dir)
	cpgPath := generateCPG(t, dir)

	cpg, err := reachability.LoadCPG(cpgPath)
	if err != nil {
		t.Fatalf("LoadCPG: %v", err)
	}

	// Verify CPG has expected structure
	if len(cpg.Vertices) == 0 {
		t.Error("Expected non-zero vertices")
	}
	if len(cpg.Edges) == 0 {
		t.Error("Expected non-zero edges")
	}

	// Should have METHOD vertices for our handler
	foundHandler := false
	foundSSHCall := false
	for _, v := range cpg.Vertices {
		name, _ := v.Properties["FULL_NAME"].(string)
		if name == "" {
			name, _ = v.Properties["METHOD_FULL_NAME"].(string)
		}
		if strings.Contains(name, "sshHandler") {
			foundHandler = true
		}
		if strings.Contains(name, "ssh.InsecureIgnoreHostKey") {
			foundSSHCall = true
		}
	}
	if !foundHandler {
		t.Error("Expected to find sshHandler METHOD vertex in CPG")
	}
	if !foundSSHCall {
		t.Error("Expected to find ssh.InsecureIgnoreHostKey CALL vertex in CPG")
	}

	// Should have CALL edges
	callEdges := 0
	for _, e := range cpg.Edges {
		if e.Label == "CALL" {
			callEdges++
		}
	}
	if callEdges == 0 {
		t.Error("Expected CALL edges in CPG")
	}
}

func TestE2E_SourceDetector_RealCPG(t *testing.T) {
	skipUnlessJoern(t)

	dir := t.TempDir()
	createVulnerableApp(t, dir)
	cpgPath := generateCPG(t, dir)

	cpg, err := reachability.LoadCPG(cpgPath)
	if err != nil {
		t.Fatalf("LoadCPG: %v", err)
	}

	det := taint.NewDetector(cpg)
	sources := det.Detect()

	if len(sources) == 0 {
		t.Fatal("Expected at least 1 source from real CPG")
	}

	// Should find HTTP handler source
	foundHTTPSource := false
	foundInputCall := false
	for _, s := range sources {
		if s.Type == taint.SourceHTTPParam {
			foundHTTPSource = true
		}
		if strings.Contains(s.Symbol, "Context.Query") {
			foundInputCall = true
		}
	}
	if !foundHTTPSource {
		t.Error("Expected to find HTTP param source")
	}
	if !foundInputCall {
		t.Error("Expected to find gin.Context.Query as input source")
	}
}

func TestE2E_FullScan_Output(t *testing.T) {
	skipUnlessJoern(t)

	dir := t.TempDir()
	createVulnerableApp(t, dir)

	bin, err := filepath.Abs("../../bin/supplychain-kit")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		build := exec.Command("go", "build", "-o", bin, "../../cmd/supplychain-kit")
		build.Dir = filepath.Dir(bin)
		if err := build.Run(); err != nil {
			t.Fatalf("build: %v", err)
		}
	}

	outFile := filepath.Join(dir, "findings.json")
	cmd := exec.Command(bin, "scan", "--repo", dir, "--format", "json", "--out", outFile)
	cmd.Stderr = os.Stderr // logs go to stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}

	var findings []models.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, string(data[:min(len(data), 500)]))
	}

	if len(findings) == 0 {
		t.Fatal("Expected findings from full scan")
	}

	// Should have confirmed_exploitable findings
	exploitableCount := 0
	for _, f := range findings {
		if f.Reachability == models.ReachConfirmedExploit {
			exploitableCount++
		}
	}
	if exploitableCount == 0 {
		t.Errorf("Expected at least 1 confirmed_exploitable finding, got 0 out of %d", len(findings))
	}

	// Should have unreachable findings for x/net
	unreachableCount := 0
	for _, f := range findings {
		if f.Reachability == models.ReachUnreachable {
			unreachableCount++
		}
	}
	if unreachableCount == 0 {
		t.Error("Expected at least 1 unreachable finding for x/net")
	}
}
