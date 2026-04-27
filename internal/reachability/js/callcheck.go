package js

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
	Evidence string // "file.js:42" or empty
}

// regexCache caches compiled import-detection regexes keyed by normalised package name.
var (
	regexCacheMu sync.Mutex
	regexCache   = map[string][3]*regexp.Regexp{}
)

func importRegexes(pkgName string) (reConst, reDefault, reStar *regexp.Regexp) {
	regexCacheMu.Lock()
	if trio, ok := regexCache[pkgName]; ok {
		regexCacheMu.Unlock()
		return trio[0], trio[1], trio[2]
	}
	regexCacheMu.Unlock()

	q := regexp.QuoteMeta(pkgName)
	rc := regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]` + q + `['"]`)
	rd := regexp.MustCompile(`import\s+(\w+)\s+from\s+['"]` + q + `['"]`)
	rs := regexp.MustCompile(`import\s+\*\s+as\s+(\w+)\s+from\s+['"]` + q + `['"]`)

	regexCacheMu.Lock()
	regexCache[pkgName] = [3]*regexp.Regexp{rc, rd, rs}
	regexCacheMu.Unlock()
	return rc, rd, rs
}

// CheckSymbolCall scans the given source files for calls to vulnerableSymbol
// from pkgName. Each file is opened exactly once (single-pass).
func CheckSymbolCall(repoPath, pkgName, vulnerableSymbol string, sourceFiles []string) CallResult {
	if vulnerableSymbol == "" {
		return CallResult{Called: false}
	}

	reConst, reDefault, reStar := importRegexes(pkgName)
	bare := barePackageName(normPkg(pkgName))
	symQ := regexp.QuoteMeta(vulnerableSymbol)

	for _, relFile := range sourceFiles {
		absFile := filepath.Join(repoPath, filepath.FromSlash(relFile))
		if evidence, found := scanFileSinglePass(absFile, bare, reConst, reDefault, reStar, vulnerableSymbol, symQ); found {
			return CallResult{Called: true, Evidence: fmt.Sprintf("%s:%s", relFile, evidence)}
		}
	}

	return CallResult{Called: false}
}

// scanFileSinglePass reads a file once, detecting import alias and checking
// for symbol calls in the same pass.
func scanFileSinglePass(filePath, bare string, reConst, reDefault, reStar *regexp.Regexp, symbol, symQ string) (string, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	alias := bare
	var lines []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		for _, re := range []*regexp.Regexp{reConst, reDefault, reStar} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				alias = m[1]
			}
		}
	}

	patterns := buildCallPatterns(alias, symbol, symQ)

	for lineNo, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
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

func buildCallPatterns(alias, symbol, symQ string) []*regexp.Regexp {
	a := regexp.QuoteMeta(alias)
	return []*regexp.Regexp{
		regexp.MustCompile(`\b` + a + `\s*\.\s*` + symQ + `\s*\(`),
		regexp.MustCompile(`\b` + a + `\s*\[\s*['"]` + symQ + `['"]\s*\]\s*\(`),
		regexp.MustCompile(`\b` + symQ + `\s*\(`),
		regexp.MustCompile(`new\s+` + a + `\s*\(`),
		regexp.MustCompile(`\b` + a + `\s*\(`),
	}
}
