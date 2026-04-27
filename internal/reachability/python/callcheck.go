package python

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// CallResult describes whether a vulnerable symbol is called in production code.
type CallResult struct {
	Called   bool
	Evidence string // "file.py:42"
}

// regexCache caches compiled alias-detection regexes keyed by normalised package name.
var (
	regexCacheMu sync.Mutex
	regexCache   = map[string][2]*regexp.Regexp{}
)

func aliasRegexes(pkgName string) (reImportAs, reFromImport *regexp.Regexp) {
	bare := bareModule(normPkg(pkgName))
	regexCacheMu.Lock()
	if pair, ok := regexCache[bare]; ok {
		regexCacheMu.Unlock()
		return pair[0], pair[1]
	}
	regexCacheMu.Unlock()

	q := regexp.QuoteMeta(bare)
	ri := regexp.MustCompile(`^\s*import\s+` + q + `(?:\s+as\s+(\w+))?`)
	rf := regexp.MustCompile(`^\s*from\s+` + q + `\s+import\s+(.+)`)

	regexCacheMu.Lock()
	regexCache[bare] = [2]*regexp.Regexp{ri, rf}
	regexCacheMu.Unlock()
	return ri, rf
}

// CheckSymbolCall scans sourceFiles for calls to vulnerableSymbol from pkgName.
// Each file is opened exactly once: aliases are detected and call patterns are
// checked in a single pass, avoiding the previous two-pass / regex-recompile overhead.
func CheckSymbolCall(repoPath, pkgName, vulnerableSymbol string, sourceFiles []string) CallResult {
	if vulnerableSymbol == "" {
		return CallResult{}
	}

	reImportAs, reFromImport := aliasRegexes(pkgName)
	bare := bareModule(normPkg(pkgName))
	symQ := regexp.QuoteMeta(vulnerableSymbol)

	for _, relFile := range sourceFiles {
		absFile := filepath.Join(repoPath, filepath.FromSlash(relFile))
		if evidence, found := scanFileSinglePass(absFile, bare, reImportAs, reFromImport, vulnerableSymbol, symQ); found {
			return CallResult{Called: true, Evidence: fmt.Sprintf("%s:%s", relFile, evidence)}
		}
	}

	return CallResult{}
}

// scanFileSinglePass reads a file once, collecting import aliases in the first
// section of the file and checking for symbol calls throughout.
func scanFileSinglePass(filePath, bare string, reImportAs, reFromImport *regexp.Regexp, symbol, symQ string) (string, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	// Collect aliases and lines in one read.
	var lines []string
	aliases := []string{}
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
		lines = append(lines, line)

		if m := reImportAs.FindStringSubmatch(line); len(m) > 0 {
			if len(m) > 1 && m[1] != "" {
				add(m[1])
			} else {
				add(bare)
			}
		}
		if m := reFromImport.FindStringSubmatch(line); len(m) > 1 {
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

	if len(aliases) == 0 {
		aliases = []string{bare}
	}

	// Build call patterns once per file (aliases now known).
	patterns := buildCallPatterns(aliases, symbol, symQ)

	for lineNo, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, pat := range patterns {
			if pat.MatchString(line) {
				return fmt.Sprintf("%d", lineNo+1), true
			}
		}
	}

	return "", false
}

func buildCallPatterns(aliases []string, symbol, symQ string) []*regexp.Regexp {
	var pats []*regexp.Regexp
	for _, alias := range aliases {
		a := regexp.QuoteMeta(alias)
		pats = append(pats, regexp.MustCompile(`\b`+a+`\s*\.\s*`+symQ+`\s*\(`))
		pats = append(pats, regexp.MustCompile(`\b`+a+`\s*\(`))
	}
	pats = append(pats, regexp.MustCompile(`\b`+symQ+`\s*\(`))
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
