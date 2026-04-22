package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// HandleBitbucketWebhook validates the shared secret, parses the event, and
// enqueues a ScanRequest. Set ASPM_BITBUCKET_WEBHOOK_SECRET to enable
// verification; when unset (dev only) we accept everything.
//
// Bitbucket Cloud sends the secret in the X-Hub-Signature header using the
// same HMAC-SHA256 scheme as GitHub, so we reuse verifySignature.
func HandleBitbucketWebhook(r *http.Request, q *Queue) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if secret := os.Getenv("ASPM_BITBUCKET_WEBHOOK_SECRET"); secret != "" {
		if !verifySignature(secret, body, r.Header.Get("X-Hub-Signature")) {
			return fmt.Errorf("invalid bitbucket signature")
		}
	}

	switch r.Header.Get("X-Event-Key") {
	case "repo:push":
		return enqueueBitbucketPush(r.Context(), q, body)
	case "pullrequest:created", "pullrequest:updated":
		return enqueueBitbucketPR(r.Context(), q, body)
	}
	return nil
}

func enqueueBitbucketPush(ctx context.Context, q *Queue, body []byte) error {
	var ev struct {
		Repository struct {
			FullName string `json:"full_name"`
			Links    struct {
				Clone []struct {
					Name string `json:"name"`
					Href string `json:"href"`
				} `json:"clone"`
			} `json:"links"`
		} `json:"repository"`
		Push struct {
			Changes []struct {
				New struct{ Name string `json:"name"` } `json:"new"`
			} `json:"changes"`
		} `json:"push"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return err
	}

	cloneURL := httpsCloneURL(ev.Repository.Links.Clone)
	ref := ""
	if len(ev.Push.Changes) > 0 {
		ref = "refs/heads/" + ev.Push.Changes[0].New.Name
	}
	return q.Enqueue(ctx, models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   ev.Repository.FullName,
		RepoURL:   cloneURL,
		Ref:       ref,
		Trigger:   "push",
		CreatedAt: time.Now().UTC(),
	})
}

func enqueueBitbucketPR(ctx context.Context, q *Queue, body []byte) error {
	var ev struct {
		Repository struct {
			FullName string `json:"full_name"`
			Links    struct {
				Clone []struct {
					Name string `json:"name"`
					Href string `json:"href"`
				} `json:"clone"`
			} `json:"links"`
		} `json:"repository"`
		PullRequest struct {
			Source struct {
				Commit struct{ Hash string `json:"hash"` } `json:"commit"`
				Repository struct {
					Links struct {
						Clone []struct {
							Name string `json:"name"`
							Href string `json:"href"`
						} `json:"clone"`
					} `json:"links"`
				} `json:"repository"`
			} `json:"source"`
		} `json:"pullrequest"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return err
	}

	cloneURL := httpsCloneURL(ev.PullRequest.Source.Repository.Links.Clone)
	if cloneURL == "" {
		cloneURL = httpsCloneURL(ev.Repository.Links.Clone)
	}
	return q.Enqueue(ctx, models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   ev.Repository.FullName,
		RepoURL:   cloneURL,
		Ref:       ev.PullRequest.Source.Commit.Hash,
		Trigger:   "pr",
		CreatedAt: time.Now().UTC(),
	})
}

// httpsCloneURL picks the https clone link from Bitbucket's clone array.
func httpsCloneURL(links []struct {
	Name string `json:"name"`
	Href string `json:"href"`
}) string {
	for _, l := range links {
		if l.Name == "https" {
			return l.Href
		}
	}
	if len(links) > 0 {
		return links[0].Href
	}
	return ""
}
