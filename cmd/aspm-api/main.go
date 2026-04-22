// Command aspm-api is the REST API + dashboard backend.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/penanamtomat/supplychain-kit/internal/api"
	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/ingestion"
	"github.com/penanamtomat/supplychain-kit/internal/quality"
	"github.com/penanamtomat/supplychain-kit/internal/storage"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
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
	gate := quality.New(cfg.QualityGate)

	h := &api.Handlers{
		Store:          store,
		Queue:          queue,
		Gate:           gate,
		RemediationURL: cfg.Remediation.BaseURL,
	}

	srv := &http.Server{
		Addr:        cfg.HTTP.Addr,
		Handler:     api.Router(h),
		ReadTimeout: time.Duration(cfg.HTTP.ReadTimeoutSec) * time.Second,
	}

	go func() {
		log.Info().Str("addr", cfg.HTTP.Addr).Msg("aspm-api listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("http server")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutting down")
	shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	_ = srv.Shutdown(shutdownCtx)
}

func redisClient(url string) *redis.Client {
	if url == "" {
		return nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		log.Warn().Err(err).Msg("invalid redis URL; running without queue")
		return nil
	}
	return redis.NewClient(opts)
}
