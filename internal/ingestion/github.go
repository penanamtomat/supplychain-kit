package ingestion

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// HandleGitHubWebhook validates the HMAC signature, parses the event, and
// enqueues a ScanRequest. Set ASPM_GITHUB_WEBHOOK_SECRET to enable signature
// verification; when unset (dev only) we accept everything.
func HandleGitHubWebhook(r *http.Request, q *Queue) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if secret := os.Getenv("ASPM_GITHUB_WEBHOOK_SECRET"); secret != "" {
		if !verifySignature(secret, body, r.Header.Get("X-Hub-Signature-256")) {
			return fmt.Errorf("invalid signature")
		}
	}

	switch r.Header.Get("X-GitHub-Event") {
	case "push":
		return enqueuePush(r.Context(), q, body)
	case "pull_request":
		return enqueuePR(r.Context(), q, body)
	}
	return nil
}

func enqueuePush(ctx context.Context, q *Queue, body []byte) error {
	var ev struct {
		Ref        string `json:"ref"`
		Repository struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return err
	}
	return q.Enqueue(ctx, models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   ev.Repository.FullName,
		RepoURL:   ev.Repository.CloneURL,
		Ref:       ev.Ref,
		Trigger:   "push",
		CreatedAt: time.Now().UTC(),
	})
}

func enqueuePR(ctx context.Context, q *Queue, body []byte) error {
	var ev struct {
		Action      string `json:"action"`
		PullRequest struct {
			Head struct {
				SHA  string `json:"sha"`
				Repo struct {
					FullName string `json:"full_name"`
					CloneURL string `json:"clone_url"`
				} `json:"repo"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return err
	}
	if ev.Action != "opened" && ev.Action != "synchronize" && ev.Action != "reopened" {
		return nil
	}
	return q.Enqueue(ctx, models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   ev.PullRequest.Head.Repo.FullName,
		RepoURL:   ev.PullRequest.Head.Repo.CloneURL,
		Ref:       ev.PullRequest.Head.SHA,
		Trigger:   "pr",
		CreatedAt: time.Now().UTC(),
	})
}

func verifySignature(secret string, body []byte, header string) bool {
	header = strings.TrimPrefix(header, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(header))
}
