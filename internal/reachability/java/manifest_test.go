package java

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// ── pom.xml tests ─────────────────────────────────────────────────────────────

func TestParsePom_TestScope(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>5.3.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>servlet-api</artifactId>
      <version>2.5</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		artifact string
		wantDev  bool
	}{
		{"spring-web", false},
		{"junit", true},
		{"servlet-api", true}, // provided scope → dev
	}
	for _, tc := range cases {
		scope, _ := m.Classify(tc.artifact)
		gotDev := scope == ScopeDevOnly
		if gotDev != tc.wantDev {
			t.Errorf("Classify(%q): dev=%v, want dev=%v", tc.artifact, gotDev, tc.wantDev)
		}
	}
}

func TestParsePom_RuntimeWinsOverTest(t *testing.T) {
	// If an artifact appears twice (runtime + test), runtime wins.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency><groupId>com.example</groupId><artifactId>mylib</artifactId></dependency>
    <dependency><groupId>com.example</groupId><artifactId>mylib</artifactId><scope>test</scope></dependency>
  </dependencies>
</project>`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := m.Classify("mylib")
	if scope != ScopeRuntime {
		t.Errorf("runtime should win over test scope, got %v", scope)
	}
}

func TestParsePom_Optional(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>optional-lib</artifactId>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := m.Classify("optional-lib")
	if scope != ScopeDevOnly {
		t.Errorf("optional dep should be ScopeDevOnly, got %v", scope)
	}
}

// ── build.gradle tests ────────────────────────────────────────────────────────

func TestParseGradle_TestImplementation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle"), `
plugins { id 'java' }

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.0.0'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
    testImplementation 'org.mockito:mockito-core:5.0.0'
    compileOnly 'org.projectlombok:lombok:1.18.0'
}
`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		artifact string
		wantDev  bool
	}{
		{"spring-boot-starter-web", false},
		{"junit-jupiter", true},
		{"mockito-core", true},
		{"lombok", true}, // compileOnly → not on runtime classpath
	}
	for _, tc := range cases {
		scope, _ := m.Classify(tc.artifact)
		gotDev := scope == ScopeDevOnly
		if gotDev != tc.wantDev {
			t.Errorf("Classify(%q): dev=%v, want dev=%v", tc.artifact, gotDev, tc.wantDev)
		}
	}
}

func TestParseGradle_KotlinDsl(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "build.gradle.kts"), `
dependencies {
    implementation("com.google.guava:guava:32.0.0-jre")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}
`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	guavaScope, _ := m.Classify("guava")
	if guavaScope != ScopeRuntime {
		t.Errorf("guava should be ScopeRuntime, got %v", guavaScope)
	}
	junitScope, _ := m.Classify("junit-jupiter")
	if junitScope != ScopeDevOnly {
		t.Errorf("junit-jupiter should be ScopeDevOnly, got %v", junitScope)
	}
}

func TestParseManifest_NeitherFileExists(t *testing.T) {
	_, err := ParseManifest(t.TempDir())
	if err == nil {
		t.Error("expected error when no manifest files exist")
	}
}

// ── normArtifact tests ────────────────────────────────────────────────────────

func TestNormArtifact(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"guava", "guava"},
		{"pkg:maven/com.google.guava/guava@32.0.0", "guava"},
		{"pkg:maven/org.springframework/spring-web@5.3.0", "spring-web"},
		{"log4j-core", "log4j-core"},
		{"LOG4J-CORE", "log4j-core"},
		{"com.example:mylib", "mylib"},
	}
	for _, tc := range cases {
		got := normArtifact(tc.in)
		if got != tc.want {
			t.Errorf("normArtifact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── extractGradleDep tests ────────────────────────────────────────────────────

func TestExtractGradleDep(t *testing.T) {
	cases := []struct {
		line       string
		wantConfig string
		wantArt    string
	}{
		{`implementation 'com.google.guava:guava:32.0.0-jre'`, "implementation", "guava"},
		{`testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")`, "testImplementation", "junit-jupiter"},
		{`api("io.ktor:ktor-server-core:2.3.0")`, "api", "ktor-server-core"},
		{`testImplementation(libs.junit)`, "testImplementation", ""},    // version catalog — skip
		{`implementation project(':submodule')`, "implementation", ""},  // project dep — skip
		{`// implementation 'foo:bar:1.0'`, "", ""},                      // comment
	}
	for _, tc := range cases {
		gotConfig, gotArt := extractGradleDep(tc.line)
		if gotConfig != tc.wantConfig || gotArt != tc.wantArt {
			t.Errorf("extractGradleDep(%q) = (%q, %q), want (%q, %q)",
				tc.line, gotConfig, gotArt, tc.wantConfig, tc.wantArt)
		}
	}
}
