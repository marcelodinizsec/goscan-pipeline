// Package ratelimit implements a minimal, dependency-free token
// bucket. It exists for study purposes: instead of importing
// golang.org/x/time/rate, we build the refill/acquire mechanics by
// hand to make the algorithm's behavior explicit.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// TokenBucket caps sustained throughput at ratePerSec while still
// allowing short bursts up to `burst` tokens. This is the classic
// mechanism for controlling vazão (throughput) independently from
// how many workers are running.
type TokenBucket struct {
	mu           sync.Mutex
	tokens       float64
	capacity     float64
	refillPerSec float64
	lastRefill   time.Time
}

// New creates a bucket allowing up to ratePerSec sustained
// events/sec, with bursts up to `burst` tokens.
func New(ratePerSec float64, burst int) *TokenBucket {
	return &TokenBucket{
		tokens:       float64(burst),
		capacity:     float64(burst),
		refillPerSec: ratePerSec,
		lastRefill:   time.Now(),
	}
}

func (b *TokenBucket) refillLocked() {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillPerSec
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastRefill = now
}

// Wait blocks until a single token is available or ctx is done,
// whichever happens first. Every scan worker calls this before
// invoking the (simulated) expensive scan operation, which is what
// actually caps end-to-end throughput regardless of worker count.
func (b *TokenBucket) Wait(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		b.mu.Lock()
		b.refillLocked()
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// retry on next tick
		}
	}
}
