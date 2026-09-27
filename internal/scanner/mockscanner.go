// Package scanner provides a mock scan engine. It stands in for a
// real detection backend (static analysis, YARA matching, sandbox
// detonation, AV engine, ...) so the pipeline's concurrency and
// flow-control mechanics can be studied and load-tested without any
// external dependency.
package scanner

import (
	"context"
	"math/rand"
	"time"

	"github.com/marcelodinizsec/goscan-pipeline/internal/model"
)

// MockEngine simulates a scan engine with configurable latency
// bounds and verdict probabilities.
type MockEngine struct {
	Name           string
	MinLatency     time.Duration
	MaxLatency     time.Duration
	MaliciousRate  float64 // probability in [0,1]
	SuspiciousRate float64 // probability in [0,1]
	rng            *rand.Rand
	mu             chan struct{} // 1-buffered mutex-like guard for rng
}

// NewMockEngine builds a mock engine. rng access is serialized with
// a 1-buffered channel because math/rand.Rand is not safe for
// concurrent use by multiple goroutines.
func NewMockEngine(name string, min, max time.Duration, maliciousRate, suspiciousRate float64) *MockEngine {
	guard := make(chan struct{}, 1)
	guard <- struct{}{}
	return &MockEngine{
		Name:           name,
		MinLatency:     min,
		MaxLatency:     max,
		MaliciousRate:  maliciousRate,
		SuspiciousRate: suspiciousRate,
		rng:            rand.New(rand.NewSource(time.Now().UnixNano())),
		mu:             guard,
	}
}

func (e *MockEngine) roll() (time.Duration, float64) {
	<-e.mu
	defer func() { e.mu <- struct{}{} }()

	d := e.MinLatency
	if e.MaxLatency > e.MinLatency {
		d += time.Duration(e.rng.Int63n(int64(e.MaxLatency - e.MinLatency)))
	}
	return d, e.rng.Float64()
}

// Scan simulates analyzing a single artifact and respects context
// cancellation so in-flight scans can be aborted on shutdown instead
// of leaking goroutines.
func (e *MockEngine) Scan(ctx context.Context, a model.Artifact) (model.Verdict, error) {
	d, roll := e.roll()

	select {
	case <-time.After(d):
	case <-ctx.Done():
		return "", ctx.Err()
	}

	switch {
	case roll < e.MaliciousRate:
		return model.VerdictMalicious, nil
	case roll < e.MaliciousRate+e.SuspiciousRate:
		return model.VerdictSuspicious, nil
	default:
		return model.VerdictClean, nil
	}
}
