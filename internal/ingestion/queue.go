// Package ingestion handles inbound work: webhook receivers translate
// provider events into ScanRequests, and Queue persists them on Redis so
// the scanner worker can pick them up.
package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

const queueKey = "aspm:scan-queue"

// Queue is a Redis-backed FIFO of ScanRequest items.
type Queue struct{ rdb *redis.Client }

// NewQueue returns a Queue using the supplied Redis client.
func NewQueue(rdb *redis.Client) *Queue { return &Queue{rdb: rdb} }

// Enqueue pushes a ScanRequest onto the queue.
func (q *Queue) Enqueue(ctx context.Context, req models.ScanRequest) error {
	if q.rdb == nil {
		return fmt.Errorf("queue not initialized")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return q.rdb.LPush(ctx, queueKey, body).Err()
}

// Dequeue blocks for up to timeoutSec until an item is available. Returns
// (nil, nil) on timeout to make caller loops trivial.
func (q *Queue) Dequeue(ctx context.Context, timeoutSec int) (*models.ScanRequest, error) {
	if q.rdb == nil {
		return nil, fmt.Errorf("queue not initialized")
	}
	res, err := q.rdb.BRPop(ctx, durationSec(timeoutSec), queueKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(res) < 2 {
		return nil, nil
	}
	var req models.ScanRequest
	if err := json.Unmarshal([]byte(res[1]), &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func durationSec(s int) time.Duration {
	return time.Duration(s) * time.Second
}
