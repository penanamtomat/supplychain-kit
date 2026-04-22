package reachability

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// RedisRuntimeConfirmer reads eBPF sensor data the platform's runtime agent
// publishes into Redis under the key:
//
//	loaded:<asset_id> -> SET of package names
//
// A real eBPF agent (uprobes on dlopen / library entry) populates this set
// and refreshes it periodically. We keep the consumer side trivial so it can
// be swapped for any other transport (NATS, Kafka) without touching the
// reachability engine.
type RedisRuntimeConfirmer struct{ rdb *redis.Client }

// NewRedisRuntimeConfirmer returns a RuntimeConfirmer backed by Redis.
func NewRedisRuntimeConfirmer(rdb *redis.Client) *RedisRuntimeConfirmer {
	return &RedisRuntimeConfirmer{rdb: rdb}
}

// IsLoaded reports whether pkg appears in the runtime-loaded set for asset.
func (r *RedisRuntimeConfirmer) IsLoaded(ctx context.Context, assetID, pkg string) (bool, error) {
	if r.rdb == nil || pkg == "" {
		return false, nil
	}
	return r.rdb.SIsMember(ctx, "loaded:"+assetID, pkg).Result()
}
