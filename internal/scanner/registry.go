package scanner

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
)

// Registry holds the active set of scanner adapters and runs them concurrently.
type Registry struct {
	scanners []Scanner
}

// NewRegistry returns a Registry seeded with the supplied adapters.
func NewRegistry(scanners ...Scanner) *Registry {
	return &Registry{scanners: scanners}
}

// RunAll executes every registered scanner concurrently. Adapter errors are
// logged and surfaced in the per-result error field so a single broken scanner
// never poisons the whole run.
func (r *Registry) RunAll(ctx context.Context, req Request) []ScannedResult {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]ScannedResult, 0, len(r.scanners))
	)
	for _, s := range r.scanners {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.Scan(ctx, req)
			if err != nil {
				log.Warn().Err(err).Str("scanner", s.Name()).Msg("scanner failed")
			}
			mu.Lock()
			results = append(results, ScannedResult{Scanner: s.Name(), Result: res, Err: err})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// ScannedResult pairs a scanner's name with its outcome.
type ScannedResult struct {
	Scanner string
	Result  Result
	Err     error
}
