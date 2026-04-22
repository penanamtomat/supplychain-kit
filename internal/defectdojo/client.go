// Package defectdojo provides a thin client for the DefectDojo REST API v2.
// It is used by the correlation layer to push de-duplicated findings into
// DefectDojo as the canonical ASOC normalization store.
package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Client is a DefectDojo API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New returns a Client targeting baseURL (e.g. "https://dojo.example.com").
// apiKey is the DefectDojo API token issued under your user profile.
func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// engagementPayload mirrors the DefectDojo /api/v2/engagements/ POST body.
type engagementPayload struct {
	Name            string `json:"name"`
	ProductID       int    `json:"product"`
	Status          string `json:"status"`
	EngagementType  string `json:"engagement_type"`
	TargetStart     string `json:"target_start"`
	TargetEnd       string `json:"target_end"`
}

// findingPayload mirrors the DefectDojo /api/v2/findings/ POST body.
type findingPayload struct {
	Title        string  `json:"title"`
	Date         string  `json:"date"`
	Severity     string  `json:"severity"`
	Description  string  `json:"description"`
	CVSSv3Score  float64 `json:"cvssv3_score,omitempty"`
	CVE          string  `json:"cve,omitempty"`
	FilePath     string  `json:"file_path,omitempty"`
	Line         int     `json:"line,omitempty"`
	Active       bool    `json:"active"`
	Verified     bool    `json:"verified"`
	EngagementID int     `json:"engagement"`
}

// EnsureEngagement creates (or returns an existing) engagement for the given
// product and scan run. In practice you would look up the engagement ID by
// name first; this implementation always creates to keep the example lean.
func (c *Client) EnsureEngagement(ctx context.Context, productID int, scanRunID string) (int, error) {
	today := time.Now().UTC().Format("2006-01-02")
	payload := engagementPayload{
		Name:           fmt.Sprintf("ASPM scan %s", scanRunID),
		ProductID:      productID,
		Status:         "In Progress",
		EngagementType: "CI/CD",
		TargetStart:    today,
		TargetEnd:      today,
	}
	body, _ := json.Marshal(payload)
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v2/engagements/", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}

	var result struct{ ID int `json:"id"` }
	if err := c.do(req, &result); err != nil {
		return 0, err
	}
	return result.ID, nil
}

// PushFindings sends all findings to DefectDojo under the given engagement.
// DefectDojo handles de-duplication internally when the same title/file/line
// combo is submitted a second time.
func (c *Client) PushFindings(ctx context.Context, engagementID int, findings []*models.Finding) error {
	for _, f := range findings {
		if err := c.pushOne(ctx, engagementID, f); err != nil {
			return fmt.Errorf("defectdojo: push finding %s: %w", f.ID, err)
		}
	}
	return nil
}

func (c *Client) pushOne(ctx context.Context, engagementID int, f *models.Finding) error {
	payload := findingPayload{
		Title:        f.Title,
		Date:         f.FirstSeen.UTC().Format("2006-01-02"),
		Severity:     titleCase(string(f.Severity)),
		Description:  f.Description,
		CVSSv3Score:  f.CVSS,
		CVE:          f.RuleID,
		FilePath:     f.FilePath,
		Line:         f.Line,
		Active:       true,
		Verified:     f.Reachability == models.ReachReachable || f.Reachability == models.ReachConfirmed,
		EngagementID: engagementID,
	}
	body, _ := json.Marshal(payload)
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v2/findings/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body *bytes.Reader) (*http.Request, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("defectdojo: unexpected status %d for %s %s", resp.StatusCode, req.Method, req.URL.Path)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func titleCase(s string) string {
	if len(s) == 0 {
		return s
	}
	return string(s[0]-32) + s[1:]
}
