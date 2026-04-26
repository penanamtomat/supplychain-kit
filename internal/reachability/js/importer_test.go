package js

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTraceImports_RequireAndImport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.js"), `
const express = require('express')
const multer = require('multer')
const path = require('path')
`)
	writeFile(t, filepath.Join(dir, "upload.ts"), `
import multer from 'multer'
import { Router } from 'express'
`)
	// Test file — must be excluded.
	if err := os.MkdirAll(filepath.Join(dir, "__tests__"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "__tests__", "server.test.js"), `
const lodash = require('lodash')
`)

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, pkg := range []string{"express", "multer"} {
		ok, _ := result.IsImported(pkg)
		if !ok {
			t.Errorf("expected %q to be imported", pkg)
		}
	}

	// lodash only appears in test file — must NOT be reported.
	ok, _ := result.IsImported("lodash")
	if ok {
		t.Error("lodash appears only in test file, should not be imported")
	}

	// path is a built-in — it starts with nothing special, but it IS in the
	// import map (we don't filter built-ins at this layer; the manifest layer
	// handles that). Just verify it doesn't cause a crash.
	_ = result.ImportedBy
}

func TestTraceImports_NodeModulesSkipped(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "somelib")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(nmDir, "index.js"), `
const secret = require('secretlib')
`)
	writeFile(t, filepath.Join(dir, "app.js"), `
const multer = require('multer')
`)

	result, err := TraceImports(dir)
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := result.IsImported("secretlib")
	if ok {
		t.Error("packages inside node_modules should be ignored")
	}
	ok, _ = result.IsImported("multer")
	if !ok {
		t.Error("multer in app.js should be detected")
	}
}

func TestIsImported_SubPathMatch(t *testing.T) {
	result := &ImportResult{
		ImportedBy: map[string][]string{
			"multer": {"/routes/upload.js"},
		},
	}

	// Exact.
	ok, _ := result.IsImported("multer")
	if !ok {
		t.Error("exact match failed")
	}

	// Sub-path import: "multer/storage" should match "multer".
	ok, _ = result.IsImported("multer/storage")
	if !ok {
		t.Error("sub-path import should match base package")
	}
}
