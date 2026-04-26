package js

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ImportResult holds which packages are imported in production source files.
type ImportResult struct {
	// ImportedBy maps package name → list of source files that import it.
	ImportedBy map[string][]string
}

// testFilePatterns are path segments that identify non-production files.
var testFilePatterns = []string{
	"__tests__",
	".test.",
	".spec.",
	"test/",
	"tests/",
	"spec/",
	"node_modules/",
	"dist/",
	"build/",
	".min.",
}

// reRequire matches: require('pkg') or require("pkg")
var reRequire = regexp.MustCompile(`require\s*\(\s*['"]([^'"./][^'"]*)['"]`)

// reImport matches: import ... from 'pkg' or import ... from "pkg"
// Also handles: import 'pkg' (side-effect imports)
var reImport = regexp.MustCompile(`(?:import\s+(?:[^'"]*\s+from\s+)?|import\s+)['"]([^'"./][^'"]*)['"]`)

// TraceImports scans all .js and .ts production files under repoPath and
// returns which packages are imported.
func TraceImports(repoPath string) (*ImportResult, error) {
	result := &ImportResult{ImportedBy: make(map[string][]string)}

	err := filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// Skip heavy directories early.
			base := strings.ToLower(d.Name())
			if base == "node_modules" || base == ".git" || base == "dist" || base == "build" || base == "coverage" {
				return filepath.SkipDir
			}
			return nil
		}

		relPath := toSlash(path[len(repoPath):])
		if isTestFile(relPath) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".ts" && ext != ".mjs" && ext != ".cjs" {
			return nil
		}

		pkgs, err := extractImports(path)
		if err != nil {
			return nil
		}

		for _, pkg := range pkgs {
			pkg = normPkg(pkg)
			result.ImportedBy[pkg] = append(result.ImportedBy[pkg], relPath)
		}
		return nil
	})

	return result, err
}

// IsImported returns true and the list of files if pkgName is imported in any
// production source file.
func (r *ImportResult) IsImported(pkgName string) (bool, []string) {
	n := normPkg(pkgName)

	// Exact match.
	if files, ok := r.ImportedBy[n]; ok {
		return true, files
	}

	// Scoped package prefix match: "@aws-sdk/client-s3" should match "aws-sdk" partially.
	// Also handle bare sub-path: "multer/storage" → "multer".
	bare := barePackageName(n)
	for imported, files := range r.ImportedBy {
		if barePackageName(imported) == bare {
			return true, files
		}
	}

	return false, nil
}

// extractImports reads a single file and returns all third-party package names
// referenced via require() or import statements.
func extractImports(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		for _, m := range reRequire.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 && !seen[m[1]] {
				seen[m[1]] = true
				pkgs = append(pkgs, m[1])
			}
		}
		for _, m := range reImport.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 && !seen[m[1]] {
				seen[m[1]] = true
				pkgs = append(pkgs, m[1])
			}
		}
	}

	return pkgs, scanner.Err()
}

// isTestFile returns true if the relative path looks like a test or non-production file.
func isTestFile(relPath string) bool {
	lower := strings.ToLower(relPath)
	for _, pattern := range testFilePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// barePackageName strips scoped prefix and sub-paths:
// "@aws-sdk/client-s3" → "client-s3"  (we also try "aws-sdk/client-s3")
// "multer/storage" → "multer"
func barePackageName(name string) string {
	// Strip sub-path (everything after the second /)
	// For scoped: "@scope/pkg/subpath" → "@scope/pkg"
	// For plain:  "pkg/subpath" → "pkg"
	parts := strings.SplitN(name, "/", 3)
	if strings.HasPrefix(name, "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func toSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
