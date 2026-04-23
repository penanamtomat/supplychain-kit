package deptrack_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/deptrack"
)

func TestClient_EnsureProject_ExistingProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("want GET, got %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{{"uuid": "abc-123", "name": "myapp", "version": "1.0"}})
	}))
	defer srv.Close()

	client := deptrack.New(srv.URL, "test-key")
	uuid, err := client.EnsureProject(context.Background(), "myapp", "1.0")
	if err != nil {
		t.Fatalf("EnsureProject() error = %v", err)
	}
	if uuid != "abc-123" {
		t.Errorf("uuid = %q, want abc-123", uuid)
	}
}

func TestClient_EnsureProject_CreatesIfAbsent(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: GET returns empty list
			_ = json.NewEncoder(w).Encode([]map[string]string{})
			return
		}
		// Second call: PUT creates project
		if r.Method != http.MethodPut {
			t.Errorf("want PUT on second call, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"uuid": "new-uuid-456", "name": "newapp", "version": "2.0"})
	}))
	defer srv.Close()

	client := deptrack.New(srv.URL, "test-key")
	uuid, err := client.EnsureProject(context.Background(), "newapp", "2.0")
	if err != nil {
		t.Fatalf("EnsureProject() error = %v", err)
	}
	if uuid != "new-uuid-456" {
		t.Errorf("uuid = %q, want new-uuid-456", uuid)
	}
	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", callCount)
	}
}

func TestClient_UploadBOM(t *testing.T) {
	var received map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("want PUT, got %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sbomData := []byte(`{"bomFormat":"CycloneDX"}`)
	client := deptrack.New(srv.URL, "test-key")
	err := client.UploadBOM(context.Background(), "proj-uuid", sbomData)
	if err != nil {
		t.Fatalf("UploadBOM() error = %v", err)
	}
	if received["project"] != "proj-uuid" {
		t.Errorf("project = %q, want proj-uuid", received["project"])
	}
	decoded, _ := base64.StdEncoding.DecodeString(received["bom"])
	if string(decoded) != string(sbomData) {
		t.Errorf("bom payload mismatch: got %q", string(decoded))
	}
}

func TestClient_GetFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		findings := []map[string]any{
			{
				"component":     map[string]string{"name": "log4j", "version": "2.14.1", "purl": "pkg:maven/log4j/log4j@2.14.1"},
				"vulnerability": map[string]any{"vulnId": "CVE-2021-44228", "severity": "CRITICAL", "cvssV3BaseScore": 10.0, "title": "Log4Shell"},
			},
		}
		_ = json.NewEncoder(w).Encode(findings)
	}))
	defer srv.Close()

	client := deptrack.New(srv.URL, "test-key")
	findings, err := client.GetFindings(context.Background(), "proj-uuid")
	if err != nil {
		t.Fatalf("GetFindings() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Vulnerability.VulnID != "CVE-2021-44228" {
		t.Errorf("vulnId = %q, want CVE-2021-44228", findings[0].Vulnerability.VulnID)
	}
}

func TestClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := deptrack.New(srv.URL, "bad-key")
	_, err := client.EnsureProject(context.Background(), "app", "1.0")
	if err == nil {
		t.Error("expected error on 401, got nil")
	}
}
