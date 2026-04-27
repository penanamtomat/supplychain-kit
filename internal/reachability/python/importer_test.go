package python

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTraceImports_BasicImports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), `
import flask
from requests import Session
import os
`)
	writeFile(t, filepath.Join(dir, "utils.py"), `
from flask import Blueprint
`)

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, pkg := range []string{"flask", "requests"} {
		ok, _ := result.IsImported(pkg)
		if !ok {
			t.Errorf("expected %q to be detected", pkg)
		}
	}
}

func TestTraceImports_TestFilesExcluded(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "tests", "test_app.py"), `
import pytest
import flask
`)
	writeFile(t, filepath.Join(dir, "app.py"), `
import requests
`)

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	// pytest only in tests/ — must not appear.
	ok, _ := result.IsImported("pytest")
	if ok {
		t.Error("pytest from tests/ should be excluded")
	}
	// flask only in tests/ — must not appear.
	ok, _ = result.IsImported("flask")
	if ok {
		t.Error("flask from tests/ should be excluded")
	}
	// requests in app.py — must appear.
	ok, _ = result.IsImported("requests")
	if !ok {
		t.Error("requests in app.py should be detected")
	}
}

func TestTraceImports_VenvSkipped(t *testing.T) {
	dir := t.TempDir()
	venvDir := filepath.Join(dir, ".venv", "lib", "python3.11", "site-packages", "flask")
	if err := os.MkdirAll(venvDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(venvDir, "app.py"), `import hidden_lib`)
	writeFile(t, filepath.Join(dir, "app.py"), `import requests`)

	result, _ := TraceImports(dir)

	ok, _ := result.IsImported("hidden_lib")
	if ok {
		t.Error("packages inside .venv should be ignored")
	}
}

func TestIsImported_KnownAlias(t *testing.T) {
	result := &ImportResult{
		ImportedBy: map[string][]string{
			"pil": {"/app/image.py"},
		},
	}
	// Pillow → PIL alias.
	ok, _ := result.IsImported("Pillow")
	if !ok {
		t.Error("Pillow should match PIL via known alias")
	}
}
