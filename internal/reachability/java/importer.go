package java

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ImportResult holds the result of scanning .java source files for import statements.
type ImportResult struct {
	// Imports maps normalized artifact name → list of source files that import it.
	Imports map[string][]string
}

// IsImported returns true if any production .java file imports the given artifact.
// Also returns the list of files that import it.
func (r *ImportResult) IsImported(artifact string) (bool, []string) {
	files, ok := r.Imports[normArtifact(artifact)]
	return ok && len(files) > 0, files
}

// TraceImports scans all production .java files under repoPath and records
// which artifacts are imported.
//
// Excluded paths (test code):
//   - src/test/       (Maven standard test sources)
//   - src/androidTest/ (Android)
//   - any file ending in Test.java or Tests.java
//   - any file starting with Test
func TraceImports(repoPath string) (*ImportResult, error) {
	result := &ImportResult{Imports: make(map[string][]string)}

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		// Skip vendor/dependency directories.
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "build" ||
				name == ".gradle" || name == "target" {
				return filepath.SkipDir
			}
			// Skip test source trees.
			rel, _ := filepath.Rel(repoPath, path)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "src/test/") ||
				strings.HasPrefix(rel, "src/androidTest/") {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".java") {
			return nil
		}

		// Skip test files by name.
		base := filepath.Base(path)
		if strings.HasPrefix(base, "Test") ||
			strings.HasSuffix(base, "Test.java") ||
			strings.HasSuffix(base, "Tests.java") ||
			strings.HasSuffix(base, "Spec.java") ||
			strings.HasSuffix(base, "IT.java") { // integration test convention
			return nil
		}

		extractImports(path, result)
		return nil
	})

	return result, err
}

// extractImports reads a .java file and records all import statements.
// Maps the top-level package group to artifact candidates.
func extractImports(path string, result *ImportResult) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import ") {
			continue
		}
		// import static com.google.guava.Foo.method; → strip "static"
		line = strings.TrimPrefix(line, "import ")
		line = strings.TrimPrefix(line, "static ")
		line = strings.TrimSuffix(line, ";")
		line = strings.TrimSpace(line)

		// e.g. "org.springframework.web.bind.annotation.GetMapping"
		// Artifact heuristic: use the 3rd segment of the package path as artifact
		// candidate (covers most Maven conventions).
		// org.springframework → spring-context (too indirect — use segment match)
		// We record both the full first-two segments and the third segment.
		parts := strings.Split(line, ".")
		if len(parts) < 2 {
			continue
		}

		// Record group.artifact candidates:
		// - parts[1] as direct artifact name (covers com.library → "library")
		// - parts[2] if present (covers org.springframework.web → "web")
		candidates := []string{parts[1]}
		if len(parts) >= 3 {
			candidates = append(candidates, parts[2])
		}

		for _, candidate := range candidates {
			if candidate == "" || candidate == "*" {
				continue
			}
			n := normArtifact(candidate)
			result.Imports[n] = appendUnique(result.Imports[n], path)
		}
	}
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
