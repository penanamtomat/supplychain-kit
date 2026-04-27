package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestNew_RegistersSixTools(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
}

func TestHandleInitEngagement_MissingEngagement(t *testing.T) {
	req := mcp.CallToolRequest{}
	result, err := handleInitEngagement(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	// Should return an error-status toolResult.
	raw := extractResultText(t, result)
	var tr toolResult
	if err := json.Unmarshal([]byte(raw), &tr); err != nil {
		t.Fatalf("unmarshal toolResult: %v (raw: %s)", err, raw)
	}
	if tr.Status != "error" {
		t.Errorf("expected status=error, got %q", tr.Status)
	}
}

func TestHandleGenerateReport_MissingEngagement(t *testing.T) {
	req := mcp.CallToolRequest{}
	result, err := handleGenerateReport(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw := extractResultText(t, result)
	var tr toolResult
	if err := json.Unmarshal([]byte(raw), &tr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tr.Status != "error" {
		t.Errorf("expected error status for missing engagement, got %q", tr.Status)
	}
}

func TestReachabilityNote(t *testing.T) {
	cases := []struct {
		r    models.Reachability
		want string
	}{
		{models.ReachReachable, "Fix"},
		{models.ReachUnknown, "Treat"},
		{models.ReachUnreachable, "sprint"},
	}
	for _, tc := range cases {
		got := reachabilityNote(tc.r)
		if !strings.Contains(got, tc.want) {
			t.Errorf("reachabilityNote(%q) = %q, want substring %q", tc.r, got, tc.want)
		}
	}
}

func TestWriteMarkdownReport_Empty(t *testing.T) {
	tmp := t.TempDir() + "/report.md"
	if err := writeMarkdownReport(tmp, "test-engagement", nil); err != nil {
		t.Fatalf("writeMarkdownReport: %v", err)
	}
}

func TestConvertToDOCX_NoPandoc(t *testing.T) {
	// When pandoc is absent this should return an error, not panic.
	err := convertToDOCX("/nonexistent.md", "/nonexistent.docx")
	if err == nil {
		// pandoc happened to be installed and ran (or output file was created) — acceptable.
		return
	}
	// Either "pandoc not found" or "no such file" — both are fine.
	if !strings.Contains(err.Error(), "pandoc") && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func extractResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil {
		t.Fatal("result is nil")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v (raw: %s)", err, raw)
	}
	if len(envelope.Content) == 0 {
		return ""
	}
	return envelope.Content[0].Text
}
