// Command aspm-scanner is the long-running worker that consumes scan jobs
// from Redis, executes the scanner pipeline, runs correlation, reachability
// analysis, scoring, and persists the result to PostgreSQL.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/correlation"
	"github.com/penanamtomat/supplychain-kit/internal/ingestion"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/gitleaks"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/grype"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/joern"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
	"github.com/penanamtomat/supplychain-kit/internal/scoring"
	"github.com/penanamtomat/supplychain-kit/internal/storage"
)

func main() {
	cfg, err := config.Load("")
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := storage.New(ctx, cfg.Database.DSN, cfg.Database.MaxConns)
	if err != nil {
		log.Fatal().Err(err).Msg("connect db")
	}
	defer store.Close()

	rdb := redisClient(cfg.Redis.URL)
	queue := ingestion.NewQueue(rdb)

	registry := scanner.NewRegistry(
		syftadapter.New(),
		grype.New(),
		semgrep.New(),
		gitleaks.New(),
		joern.New(),
	)
	reach := reachability.New(reachability.NewRedisRuntimeConfirmer(rdb))
	scorer := scoring.Scorer{}

	log.Info().Msg("aspm-scanner started")
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down")
			return
		default:
		}

		req, err := queue.Dequeue(ctx, 5)
		if err != nil {
			log.Warn().Err(err).Msg("dequeue")
			continue
		}
		if req == nil {
			continue
		}
		if err := processJob(ctx, store, registry, reach, scorer, *req); err != nil {
			log.Error().Err(err).Str("scan", req.ID).Msg("job failed")
		}
	}
}

func processJob(
	ctx context.Context,
	store *storage.Store,
	reg *scanner.Registry,
	reach *reachability.Engine,
	scorer scoring.Scorer,
	req models.ScanRequest,
) error {
	log.Info().Str("repo", req.RepoURL).Str("ref", req.Ref).Msg("scan start")

	asset, err := store.GetAsset(ctx, req.AssetID)
	if err != nil {
		// Auto-register the asset on first sight so demos don't require
		// an explicit POST /assets call.
		asset = &models.Asset{
			ID: req.AssetID, Name: req.AssetID, RepoURL: req.RepoURL,
			Environment: models.EnvDev, Tier: 2,
		}
		_ = store.UpsertAsset(ctx, asset)
	}

	results, artifacts, cleanup, err := reg.RunPipeline(ctx, asset, req.Ref)
	if err != nil {
		return err
	}
	defer cleanup()

	merged := correlation.Merge(results)

	if err := reach.Analyze(ctx, asset.ID, artifacts[joern.ArtifactCPGPath], merged); err != nil {
		log.Warn().Err(err).Msg("reachability")
	}

	for _, f := range merged {
		scorer.Score(f, asset)
		if err := store.UpsertFinding(ctx, f); err != nil {
			log.Warn().Err(err).Str("fingerprint", f.Fingerprint).Msg("upsert finding")
		}
	}

	if sbomPath := artifacts[syftadapter.ArtifactSBOMPath]; sbomPath != "" {
		if sb, err := syftadapter.LoadSBOM(sbomPath, asset.ID); err == nil {
			_ = store.StoreSBOM(ctx, sb)
		}
	}

	log.Info().Int("findings", len(merged)).Str("repo", req.RepoURL).Msg("scan done")
	return nil
}

func redisClient(url string) *redis.Client {
	if url == "" {
		return nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid redis URL")
	}
	return redis.NewClient(opts)
}
