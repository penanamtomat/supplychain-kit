package ingestion

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// HandleGitLabWebhook validates the X-Gitlab-Token secret, parses the event,
// and enqueues a ScanRequest. Set ASPM_GITLAB_WEBHOOK_SECRET to enable token
// verification; when unset (dev only) we accept everything.
func HandleGitLabWebhook(r *http.Request, q *Queue) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if secret := os.Getenv("ASPM_GITLAB_WEBHOOK_SECRET"); secret != "" {
		token := r.Header.Get("X-Gitlab-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
			return fmt.Errorf("invalid gitlab token")
		}
	}

	switch r.Header.Get("X-Gitlab-Event") {
	case "Push Hook", "Tag Push Hook":
		return enqueueGitLabPush(r.Context(), q, body)
	case "Merge Request Hook":
		return enqueueGitLabMR(r.Context(), q, body)
	}
	return nil
}

func enqueueGitLabPush(ctx context.Context, q *Queue, body []byte) error {
	var ev struct {
		Ref     string `json:"ref"`
		Project struct {
			PathWithNamespace string `json:"path_with_namespace"`
			HTTPURLToRepo     string `json:"http_url_to_repo"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return err
	}
	return q.Enqueue(ctx, models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   ev.Project.PathWithNamespace,
		RepoURL:   ev.Project.HTTPURLToRepo,
		Ref:       ev.Ref,
		Trigger:   "push",
		CreatedAt: time.Now().UTC(),
	})
}

func enqueueGitLabMR(ctx context.Context, q *Queue, body []byte) error {
	var ev struct {
		ObjectAttributes struct {
			Action       string `json:"action"`
			LastCommit   struct{ ID string `json:"id"` } `json:"last_commit"`
			Source       struct {
				PathWithNamespace string `json:"path_with_namespace"`
				HTTPURLToRepo     string `json:"http_url_to_repo"`
			} `json:"source"`
		} `json:"object_attributes"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return err
	}
	action := ev.ObjectAttributes.Action
	if action != "open" && action != "update" && action != "reopen" {
		return nil
	}
	return q.Enqueue(ctx, models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   ev.ObjectAttributes.Source.PathWithNamespace,
		RepoURL:   ev.ObjectAttributes.Source.HTTPURLToRepo,
		Ref:       ev.ObjectAttributes.LastCommit.ID,
		Trigger:   "pr",
		CreatedAt: time.Now().UTC(),
	})
}
