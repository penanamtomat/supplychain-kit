// Package api exposes the REST surface for the ASPM platform: scan
// orchestration, finding queries, asset CRUD, quality-gate evaluation, and
// VEX delegation to the remediation service.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Router builds the HTTP router with all handlers wired in.
func Router(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	r.Get("/health", h.Health)
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/scans", h.CreateScan)
		r.Get("/scans/{id}", h.GetScan)

		r.Get("/findings", h.ListFindings)
		r.Get("/findings/{id}", h.GetFinding)

		r.Post("/assets", h.UpsertAsset)
		r.Get("/assets/{id}", h.GetAsset)
		r.Get("/assets/{id}/risk", h.AssetRisk)

		r.Post("/quality-gate/evaluate", h.EvaluateGate)
		r.Post("/vex", h.RequestVEX)

		r.Post("/webhooks/github", h.GithubWebhook)
		r.Post("/webhooks/gitlab", h.GitlabWebhook)
		r.Post("/webhooks/bitbucket", h.BitbucketWebhook)

		r.Post("/agentic-sast", h.AgenticSAST)
	})
	return r
}

// writeJSON is a small helper used by every handler.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
