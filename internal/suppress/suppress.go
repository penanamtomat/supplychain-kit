// Package suppress implements a .supplychain-ignore file parser and matcher.
//
// Format (one rule per line, # for comments):
//
//	# Accepted as false positive — input is a constant, not user-controlled
//	CVE-2023-12345
//	semgrep.tainted-sql  path:internal/legacy/*.go
//	*  package:github.com/dead/pkg   reason:unmaintained, isolated in dev-only code
//
// Tokens:
//
//	<rule>                             first bare token: rule ID glob ("*" = any)
//	path:<glob>                        match Finding.FilePath
//	package:<glob>                     match Finding.Package
//	fingerprint:<value>                exact match Finding.Fingerprint
//	reason:<free text until EOL>       recorded on suppressed findings
//
// Matching is AND across tokens on a line; OR across lines.
package suppress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Rule is a single suppression rule parsed from the ignore file.
type Rule struct {
	RuleID      string // glob on Finding.RuleID ("*" = any)
	Path        string // glob on Finding.FilePath (empty = any)
	Package     string // glob on Finding.Package (empty = any)
	Fingerprint string // exact match on Finding.Fingerprint (empty = any)
	Reason      string
	SourceLine  int
}

// Set is the compiled suppression ruleset.
type Set struct {
	rules []Rule
	path  string
}

// DefaultFilename is the filename Load looks for when given a directory.
const DefaultFilename = ".supplychain-ignore"

// Load reads and parses the ignore file. If path is a directory, DefaultFilename
// is appended. A missing file returns an empty set (no error) — suppression is
// always opt-in.
func Load(path string) (*Set, error) {
	if path == "" {
		return &Set{}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Set{}, nil
		}
		return nil, err
	}
	if info.IsDir() {
		path = filepath.Join(path, DefaultFilename)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return &Set{}, nil
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := &Set{path: path}
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseLine(line, lineNum)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNum, err)
		}
		s.rules = append(s.rules, rule)
	}
	return s, sc.Err()
}

func parseLine(line string, lineNum int) (Rule, error) {
	r := Rule{SourceLine: lineNum}
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return r, fmt.Errorf("empty rule")
	}
	r.RuleID = tokens[0]
	for _, tok := range tokens[1:] {
		key, value, ok := strings.Cut(tok, ":")
		if !ok {
			return r, fmt.Errorf("unrecognized token %q (expected key:value)", tok)
		}
		switch strings.ToLower(key) {
		case "path":
			r.Path = value
		case "package":
			r.Package = value
		case "fingerprint":
			r.Fingerprint = value
		case "reason":
			r.Reason = value
		default:
			return r, fmt.Errorf("unknown key %q (use path|package|fingerprint|reason)", key)
		}
	}
	return r, nil
}

// tokenize splits by whitespace but keeps the trailing reason:... as one token.
func tokenize(line string) []string {
	var out []string
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		// reason:... consumes to EOL.
		if strings.HasPrefix(strings.ToLower(line[i:]), "reason:") {
			out = append(out, line[i:])
			break
		}
		j := i
		for j < len(line) && line[j] != ' ' && line[j] != '\t' {
			j++
		}
		out = append(out, line[i:j])
		i = j
	}
	return out
}

// Apply marks matching findings as suppressed using VEX status. Returns the
// count of findings suppressed. Findings are not removed — downstream tools
// can choose to filter by vex_status.
func (s *Set) Apply(findings []*models.Finding) int {
	if s == nil || len(s.rules) == 0 {
		return 0
	}
	count := 0
	for _, f := range findings {
		if f == nil {
			continue
		}
		if rule, ok := s.match(f); ok {
			f.VEXStatus = models.VEXNotAffected
			f.VEXJustify = models.VEXJustNotInExecutionPath
			if f.Raw == nil {
				f.Raw = map[string]any{}
			}
			f.Raw["suppressed_by"] = map[string]any{
				"source":  s.path,
				"line":    rule.SourceLine,
				"rule_id": rule.RuleID,
				"reason":  rule.Reason,
			}
			count++
		}
	}
	return count
}

func (s *Set) match(f *models.Finding) (Rule, bool) {
	for _, r := range s.rules {
		if r.Fingerprint != "" && r.Fingerprint != f.Fingerprint {
			continue
		}
		if !globMatch(r.RuleID, f.RuleID) {
			continue
		}
		if r.Path != "" && !globMatch(r.Path, f.FilePath) {
			continue
		}
		if r.Package != "" && !globMatch(r.Package, f.Package) {
			continue
		}
		return r, true
	}
	return Rule{}, false
}

// globMatch supports "*" as wildcard; falls back to filepath.Match for
// structured globs like "internal/*/foo.go".
func globMatch(pattern, s string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == s {
		return true
	}
	ok, err := filepath.Match(pattern, s)
	if err == nil && ok {
		return true
	}
	return strings.Contains(s, strings.Trim(pattern, "*"))
}

// Len returns the number of rules in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}
