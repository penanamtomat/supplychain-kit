package js

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
	Evidence string // "file.js:42" or empty
}

// CheckSymbolCall scans the given source files for calls to vulnerableSymbol
// from pkgName. It uses two strategies:
//
//  1. Bound call: identifier returned by require/import is used as
//     `<alias>.vulnerableSymbol(` or `<alias>['vulnerableSymbol'](`.
//  2. Bare call: `vulnerableSymbol(` appears in any file that imports pkgName
//     (lower confidence but catches destructured imports).
func CheckSymbolCall(repoPath, pkgName, vulnerableSymbol string, sourceFiles []string) CallResult {
	if vulnerableSymbol == "" {
		// No symbol → can only say "imported but symbol unknown"
		return CallResult{Called: false}
	}

	for _, relFile := range sourceFiles {
		absFile := filepath.Join(repoPath, filepath.FromSlash(relFile))

		alias := findImportAlias(absFile, pkgName)
		evidence, found := scanFileForCall(absFile, alias, vulnerableSymbol)
		if found {
			return CallResult{Called: true, Evidence: fmt.Sprintf("%s:%s", relFile, evidence)}
		}
	}

	return CallResult{Called: false}
}

// findImportAlias extracts the local variable name used when importing pkgName.
//
//	const multer = require('multer')  → "multer"
//	import upload from 'multer'       → "upload"
//	import * as m from 'multer'       → "m"
//	import { merge } from 'lodash'    → "merge" (named import, check bare)
func findImportAlias(filePath, pkgName string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return barePackageName(normPkg(pkgName))
	}
	defer f.Close()

	bare := barePackageName(normPkg(pkgName))
	quotedPkg := regexp.QuoteMeta(pkgName)

	// const X = require('pkg')  or  var X = require('pkg')
	reConst := regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]` + quotedPkg + `['"]`)
	// import X from 'pkg'
	reDefault := regexp.MustCompile(`import\s+(\w+)\s+from\s+['"]` + quotedPkg + `['"]`)
	// import * as X from 'pkg'
	reStar := regexp.MustCompile(`import\s+\*\s+as\s+(\w+)\s+from\s+['"]` + quotedPkg + `['"]`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, re := range []*regexp.Regexp{reConst, reDefault, reStar} {
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				return m[1]
			}
		}
	}

	return bare
}

// scanFileForCall looks for calls to `alias.symbol(`, `symbol(` or `alias['symbol'](`
// Returns the line number and true if found.
func scanFileForCall(filePath, alias, symbol string) (string, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	// Patterns to match (order: most specific first).
	patterns := buildCallPatterns(alias, symbol)

	lineNo := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		// Skip comment lines.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
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

// buildCallPatterns returns regexes that would match a call to symbol via alias.
func buildCallPatterns(alias, symbol string) []*regexp.Regexp {
	a := regexp.QuoteMeta(alias)
	s := regexp.QuoteMeta(symbol)

	patterns := []*regexp.Regexp{
		// multer.merge(  or  multer.merge (
		regexp.MustCompile(`\b` + a + `\s*\.\s*` + s + `\s*\(`),
		// multer['merge'](
		regexp.MustCompile(`\b` + a + `\s*\[\s*['"]` + s + `['"]\s*\]\s*\(`),
		// bare symbol call: merge(  — only if alias == symbol (destructured import)
		regexp.MustCompile(`\b` + s + `\s*\(`),
		// new multer()  — constructor call
		regexp.MustCompile(`new\s+` + a + `\s*\(`),
		// multer()  — package itself is callable (e.g. express())
		regexp.MustCompile(`\b` + a + `\s*\(`),
	}

	return patterns
}
