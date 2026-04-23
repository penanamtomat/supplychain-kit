package reachability

import "context"

// NoopRuntimeConfirmer is a no-op implementation of RuntimeConfirmer used when
// no eBPF runtime sensor is available. It always reports packages as not loaded,
// causing the engine to fall back to static CPG analysis only.
type NoopRuntimeConfirmer struct{}

// IsLoaded always returns false — no runtime data available.
func (n *NoopRuntimeConfirmer) IsLoaded(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
