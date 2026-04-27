// Package java implements the 3-layer Static Import Graph reachability analyzer
// for Java (Maven/Gradle ecosystem).
package java

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// PackageScope classifies a Maven/Gradle dependency by its build scope.
type PackageScope string

const (
	ScopeRuntime PackageScope = "runtime"
	ScopeDevOnly PackageScope = "devonly" // test / provided / optional
)

// ManifestResult holds scope classification for all declared dependencies.
type ManifestResult struct {
	Scope map[string]PackageScope // artifactId (normalized) → scope
}

// Classify returns the scope for a given artifact name.
// Returns ScopeRuntime, false when the artifact is not found.
func (m *ManifestResult) Classify(artifact string) (PackageScope, bool) {
	scope, ok := m.Scope[normArtifact(artifact)]
	if !ok {
		return ScopeRuntime, false
	}
	return scope, true
}

// ParseManifest reads pom.xml and/or build.gradle[.kts] from repoPath and
// returns scope classification.  Both files are parsed when present; runtime
// scope always wins over test scope.
func ParseManifest(repoPath string) (*ManifestResult, error) {
	result := &ManifestResult{Scope: make(map[string]PackageScope)}

	pomErr := parsePom(repoPath, result)
	gradleErr := parseGradle(repoPath, result)

	if pomErr != nil && gradleErr != nil {
		return nil, pomErr // report pom error as primary
	}
	return result, nil
}

// ── pom.xml ───────────────────────────────────────────────────────────────────

type mavenPom struct {
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Scope      string `xml:"scope"`
		Optional   string `xml:"optional"`
	} `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Scope      string `xml:"scope"`
		} `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
}

// devScopes lists Maven scopes that indicate dev/test-only usage.
var devScopes = map[string]bool{
	"test":     true,
	"provided": true, // compile-time only, provided by container at runtime
}

func parsePom(repoPath string, result *ManifestResult) error {
	data, err := os.ReadFile(filepath.Join(repoPath, "pom.xml"))
	if err != nil {
		return err
	}

	var pom mavenPom
	if err := xml.Unmarshal(data, &pom); err != nil {
		return err
	}

	for _, dep := range pom.Dependencies {
		if dep.ArtifactID == "" {
			continue
		}
		n := normArtifact(dep.ArtifactID)
		scope := strings.ToLower(strings.TrimSpace(dep.Scope))
		optional := strings.ToLower(strings.TrimSpace(dep.Optional)) == "true"

		if devScopes[scope] || optional {
			// Only mark dev if not already pinned as runtime.
			if existing, ok := result.Scope[n]; !ok || existing != ScopeRuntime {
				result.Scope[n] = ScopeDevOnly
			}
		} else {
			result.Scope[n] = ScopeRuntime
		}
	}
	return nil
}

// ── build.gradle / build.gradle.kts ──────────────────────────────────────────

// gradleDevConfigs lists Gradle configuration names that are dev/test-only.
var gradleDevConfigs = []string{
	"testimplementation",
	"testapi",
	"testcompileonly",
	"testruntime",
	"testruntimeonly",
	"androidtestimplementation",
	"debugimplementation",
	"compileonly",       // like Maven provided — not on runtime classpath
}

// gradleRuntimeConfigs lists Gradle configurations present at runtime.
var gradleRuntimeConfigs = []string{
	"implementation",
	"api",
	"runtimeonly",
	"compile", // deprecated but still found in older projects
}

func parseGradle(repoPath string, result *ManifestResult) error {
	// Try build.gradle and build.gradle.kts.
	candidates := []string{
		filepath.Join(repoPath, "build.gradle"),
		filepath.Join(repoPath, "build.gradle.kts"),
	}

	var found bool
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		parseGradleContent(string(data), result)
	}

	if !found {
		return os.ErrNotExist
	}
	return nil
}

// parseGradleContent parses Gradle dependency lines using regex-free heuristics.
// Handles both Groovy DSL: implementation 'group:artifact:version'
// and Kotlin DSL:           implementation("group:artifact:version")
func parseGradleContent(content string, result *ManifestResult) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}

		config, artifact := extractGradleDep(line)
		if artifact == "" {
			continue
		}

		n := normArtifact(artifact)
		configLow := strings.ToLower(config)

		isDev := false
		for _, devCfg := range gradleDevConfigs {
			if configLow == devCfg || strings.HasPrefix(configLow, devCfg) {
				isDev = true
				break
			}
		}

		if isDev {
			if existing, ok := result.Scope[n]; !ok || existing != ScopeRuntime {
				result.Scope[n] = ScopeDevOnly
			}
		} else {
			// Only set runtime if this is a known runtime config.
			isRuntime := false
			for _, rtCfg := range gradleRuntimeConfigs {
				if configLow == rtCfg {
					isRuntime = true
					break
				}
			}
			if isRuntime {
				result.Scope[n] = ScopeRuntime
			}
		}
	}
}

// extractGradleDep parses a single Gradle dependency line and returns
// (configuration, artifactId). Returns ("", "") if not a dep line at all.
// Returns (config, "") when the line is a known dep line but has no resolvable
// artifact (version catalog, project dep, etc.).
//
// Handles formats:
//   implementation 'com.google.guava:guava:32.0.0-jre'
//   implementation("com.google.guava:guava:32.0.0-jre")
//   testImplementation(libs.junit)     ← version catalog → (config, "")
//   api project(':submodule')          ← project dep    → (config, "")
func extractGradleDep(line string) (config, artifact string) {
	// Reject comment lines before any other processing.
	if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
		return "", ""
	}

	// Find the configuration keyword at the start of the line.
	var configEnd int
	for i, ch := range line {
		if ch == ' ' || ch == '(' || ch == '\t' {
			configEnd = i
			break
		}
	}
	if configEnd == 0 {
		return "", ""
	}
	config = line[:configEnd]

	// Extract the coordinate string (quoted or in parens).
	rest := strings.TrimSpace(line[configEnd:])
	rest = strings.TrimPrefix(rest, "(")
	rest = strings.TrimSuffix(rest, ")")
	rest = strings.Trim(rest, `'"`)
	rest = strings.TrimSpace(rest)

	// Skip project() and version catalog (libs.) refs — no coordinate to parse.
	// Return (config, "") so the caller knows this is a dep line, just unresolvable.
	if strings.HasPrefix(rest, "project(") ||
		strings.HasPrefix(rest, "libs.") ||
		!strings.Contains(rest, ":") {
		return config, ""
	}

	// group:artifact:version — extract artifact (middle segment).
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) < 2 || parts[1] == "" {
		return config, ""
	}
	return config, parts[1]
}

// normArtifact lowercases and trims an artifact ID.
// Also handles purl: pkg:maven/group/artifact@version → artifact
func normArtifact(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if after, ok := strings.CutPrefix(name, "pkg:maven/"); ok {
		// pkg:maven/com.google.guava/guava@32.0.0 → guava
		parts := strings.SplitN(after, "/", 2)
		if len(parts) == 2 {
			artifact := parts[1]
			if idx := strings.Index(artifact, "@"); idx > 0 {
				artifact = artifact[:idx]
			}
			return artifact
		}
	}
	// Strip version suffix if present.
	if idx := strings.Index(name, "@"); idx > 0 {
		name = name[:idx]
	}
	// If it's a group:artifact format, return just the artifact.
	if idx := strings.LastIndex(name, ":"); idx > 0 {
		name = name[idx+1:]
	}
	return name
}
