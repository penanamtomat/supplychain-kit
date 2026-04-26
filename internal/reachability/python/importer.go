package python

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ImportResult holds which packages are imported in production source files.
type ImportResult struct {
	// ImportedBy maps normalised package name → list of source files.
	ImportedBy map[string][]string
}

// testFilePatterns are path segments identifying non-production Python files.
var testFilePatterns = []string{
	"test_",
	"_test.py",
	"/tests/",
	"/test/",
	"conftest.py",
	"setup.py",
	"setup.cfg",
	"/.tox/",
	"/__pycache__/",
	"/site-packages/",
}

// reImport matches "import pkg" or "import pkg.sub"
var reImport = regexp.MustCompile(`^\s*import\s+([\w.]+)`)

// reFromImport matches "from pkg import ..." or "from pkg.sub import ..."
var reFromImport = regexp.MustCompile(`^\s*from\s+([\w.]+)\s+import`)

// TraceImports walks all .py files under repoPath (excluding test files) and
// returns which top-level packages are imported.
func TraceImports(repoPath string) (*ImportResult, error) {
	result := &ImportResult{ImportedBy: make(map[string][]string)}

	err := filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == ".tox" || base == "__pycache__" ||
				base == ".venv" || base == "venv" || base == "env" ||
				base == "site-packages" || base == "dist" || base == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(path), ".py") {
			return nil
		}

		relPath := toSlash(path[len(repoPath):])
		if isTestFile(relPath) {
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

// IsImported returns true and files if pkgName is imported in any production file.
// Handles PyPI normalisation (underscores ↔ hyphens) and top-level module matching.
func (r *ImportResult) IsImported(pkgName string) (bool, []string) {
	n := normPkg(pkgName)

	// Exact match (both already normalised).
	if files, ok := r.ImportedBy[n]; ok {
		return true, files
	}

	// Some packages expose a different import name vs PyPI name
	// (e.g. "Pillow" → "PIL", "scikit-learn" → "sklearn").
	// We try common aliases.
	for alias, canonical := range knownAliases {
		if canonical == n {
			if files, ok := r.ImportedBy[normPkg(alias)]; ok {
				return true, files
			}
		}
		if normPkg(alias) == n {
			if files, ok := r.ImportedBy[normPkg(canonical)]; ok {
				return true, files
			}
		}
	}

	// Prefix match: "requests-toolbelt" may be imported as "requests_toolbelt" or just "requests".
	// Only match if the imported module starts with the package name.
	for imported, files := range r.ImportedBy {
		if strings.HasPrefix(imported, n) || strings.HasPrefix(n, imported) {
			return true, files
		}
	}

	return false, nil
}

// extractImports reads a single .py file and returns top-level package names.
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

		if m := reImport.FindStringSubmatch(line); len(m) > 1 {
			pkg := topLevel(m[1])
			if !seen[pkg] {
				seen[pkg] = true
				pkgs = append(pkgs, pkg)
			}
		}
		if m := reFromImport.FindStringSubmatch(line); len(m) > 1 {
			pkg := topLevel(m[1])
			if !seen[pkg] {
				seen[pkg] = true
				pkgs = append(pkgs, pkg)
			}
		}
	}

	return pkgs, scanner.Err()
}

// topLevel returns the top-level package name from a dotted module path:
// "os.path" → "os", "flask.request" → "flask".
func topLevel(module string) string {
	if idx := strings.Index(module, "."); idx > 0 {
		return module[:idx]
	}
	return module
}

func isTestFile(relPath string) bool {
	lower := strings.ToLower(relPath)
	for _, p := range testFilePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func toSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// knownAliases maps PyPI package name ↔ import module name for packages that differ.
var knownAliases = map[string]string{
	"Pillow":        "PIL",
	"scikit-learn":  "sklearn",
	"scikit-image":  "skimage",
	"pyyaml":        "yaml",
	"beautifulsoup4": "bs4",
	"python-dateutil": "dateutil",
	"pyzmq":         "zmq",
	"opencv-python": "cv2",
}
