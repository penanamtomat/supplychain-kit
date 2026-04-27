package java

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SymbolCallResult holds the result of a symbol call search in source files.
type SymbolCallResult struct {
	Found    bool
	Evidence string // "relative/path/to/File.java:lineN"
}

// CheckSymbolCall scans the given production source files for uses of the
// vulnerable symbol (class name or method name). Case-insensitive match.
//
// For Java, we look for the simple name (e.g. "JndiLookup") rather than the
// fully-qualified name because import statements are already recorded.
func CheckSymbolCall(repoPath, symbol string, sourceFiles []string) SymbolCallResult {
	pattern := strings.ToLower(symbol)
	for _, file := range sourceFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(strings.ToLower(line), pattern) {
				rel := file
				if r, err2 := filepath.Rel(repoPath, file); err2 == nil {
					rel = filepath.ToSlash(r)
				}
				return SymbolCallResult{
					Found:    true,
					Evidence: fmt.Sprintf("%s:%d", rel, i+1),
				}
			}
		}
	}
	return SymbolCallResult{}
}
