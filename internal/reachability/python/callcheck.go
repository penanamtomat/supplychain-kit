package python

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CallResult describes whether a vulnerable symbol is called in production code.
type CallResult struct {
	Called   bool
	Evidence string // "file.py:42"
}

// CheckSymbolCall scans sourceFiles for calls to vulnerableSymbol from pkgName.
//
// Strategy:
//  1. Find the local alias used when importing pkgName in each file.
//  2. Look for `alias.symbol(` or `from pkg import symbol` + bare `symbol(`.
func CheckSymbolCall(repoPath, pkgName, vulnerableSymbol string, sourceFiles []string) CallResult {
	if vulnerableSymbol == "" {
		return CallResult{}
	}

	for _, relFile := range sourceFiles {
		absFile := filepath.Join(repoPath, filepath.FromSlash(relFile))

		aliases := findImportAliases(absFile, pkgName)
		if len(aliases) == 0 {
			// Fallback: use the package base name as alias.
			aliases = []string{bareModule(normPkg(pkgName))}
		}

		evidence, found := scanFileForCall(absFile, aliases, vulnerableSymbol)
		if found {
			return CallResult{Called: true, Evidence: fmt.Sprintf("%s:%s", relFile, evidence)}
		}
	}

	return CallResult{}
}

// findImportAliases returns all local names under which pkgName is available:
//
//	import pkg           → ["pkg"]
//	import pkg as alias  → ["alias"]
//	from pkg import sym  → ["sym"] (symbol itself is directly bound)
//	from pkg import sym as s → ["s"]
func findImportAliases(filePath, pkgName string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	bare := bareModule(normPkg(pkgName))
	quotedBare := regexp.QuoteMeta(bare)

	// import pkg  or  import pkg as alias
	reImportAs := regexp.MustCompile(`^\s*import\s+` + quotedBare + `(?:\s+as\s+(\w+))?`)
	// from pkg import sym [as alias]
	reFromImport := regexp.MustCompile(`^\s*from\s+` + quotedBare + `\s+import\s+(.+)`)

	var aliases []string
	seen := make(map[string]bool)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			aliases = append(aliases, s)
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if m := reImportAs.FindStringSubmatch(line); len(m) > 0 {
			if len(m) > 1 && m[1] != "" {
				add(m[1]) // aliased: import pkg as alias
			} else {
				add(bare) // plain: import pkg
			}
		}

		if m := reFromImport.FindStringSubmatch(line); len(m) > 1 {
			// Parse: sym1, sym2, sym1 as s1 ...
			for _, part := range strings.Split(m[1], ",") {
				part = strings.TrimSpace(part)
				if asParts := strings.Fields(part); len(asParts) == 3 && strings.EqualFold(asParts[1], "as") {
					add(asParts[2])
				} else if len(asParts) >= 1 {
					add(asParts[0])
				}
			}
		}
	}

	return aliases
}

// scanFileForCall looks for calls using any of the given aliases.
func scanFileForCall(filePath string, aliases []string, symbol string) (string, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	patterns := buildCallPatterns(aliases, symbol)

	lineNo := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, pat := range patterns {
			if pat.MatchString(line) {
				return fmt.Sprintf("%d", lineNo), true
			}
		}
	}

	return "", false
}

func buildCallPatterns(aliases []string, symbol string) []*regexp.Regexp {
	s := regexp.QuoteMeta(symbol)
	var pats []*regexp.Regexp

	for _, alias := range aliases {
		a := regexp.QuoteMeta(alias)
		// alias.symbol(
		pats = append(pats, regexp.MustCompile(`\b`+a+`\s*\.\s*`+s+`\s*\(`))
		// alias(  — package itself is callable
		pats = append(pats, regexp.MustCompile(`\b`+a+`\s*\(`))
	}

	// Bare symbol call (when imported directly: from pkg import symbol)
	pats = append(pats, regexp.MustCompile(`\b`+s+`\s*\(`))

	return pats
}

// bareModule strips sub-module paths: "requests.adapters" → "requests"
// and normalises the result.
func bareModule(name string) string {
	if idx := strings.Index(name, "."); idx > 0 {
		return name[:idx]
	}
	return name
}
