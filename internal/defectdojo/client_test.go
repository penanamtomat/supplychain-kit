package defectdojo_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/penanamtomat/supplychain-kit/internal/defectdojo"
	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestClient_EnsureEngagement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("want POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]int{"id": 42})
	}))
	defer srv.Close()

	client := defectdojo.New(srv.URL, "test-token")
	eid, err := client.EnsureEngagement(context.Background(), 1, "scan-run-001")
	if err != nil {
		t.Fatalf("EnsureEngagement() error = %v", err)
	}
	if eid != 42 {
		t.Errorf("engagement id = %d, want 42", eid)
	}
}

func TestClient_PushFindings(t *testing.T) {
	var received []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		received = append(received, payload)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	findings := []*models.Finding{
		{
			ID:           "f1",
			AssetID:      "test",
			RuleID:       "CVE-2021-44228",
			Title:        "Log4Shell",
			Severity:     models.SeverityCritical,
			Package:      "log4j",
			FilePath:     "pom.xml",
			Line:         10,
			Reachability: models.ReachReachable,
			FirstSeen:    time.Now(),
		},
	}

	client := defectdojo.New(srv.URL, "test-token")
	err := client.PushFindings(context.Background(), 42, findings)
	if err != nil {
		t.Fatalf("PushFindings() error = %v", err)
	}
	if len(received) != 1 {
		t.Fatalf("want 1 POST, got %d", len(received))
	}
	if received[0]["title"] != "Log4Shell" {
		t.Errorf("title = %q, want Log4Shell", received[0]["title"])
	}
	if received[0]["cve"] != "CVE-2021-44228" {
		t.Errorf("cve = %q, want CVE-2021-44228", received[0]["cve"])
	}
	// Reachable finding should be verified = true
	if verified, _ := received[0]["verified"].(bool); !verified {
		t.Error("reachable finding should be verified=true in DefectDojo")
	}
}

func TestClient_PushFindings_Empty(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
	}))
	defer srv.Close()

	client := defectdojo.New(srv.URL, "test-token")
	err := client.PushFindings(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("PushFindings(nil) error = %v", err)
	}
	if callCount != 0 {
		t.Errorf("expected no HTTP calls for empty findings, got %d", callCount)
	}
}

func TestClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := defectdojo.New(srv.URL, "bad-token")
	_, err := client.EnsureEngagement(context.Background(), 1, "run-1")
	if err == nil {
		t.Error("expected error on 403, got nil")
	}
}
