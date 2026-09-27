// Package pipeline wires together the stages of the scanning
// pipeline using the classic Go "pipeline" and "fan-out/fan-in"
// concurrency patterns: each stage is a function that takes an
// input channel and returns an output channel, and stages are
// composed by feeding one into the next.
package pipeline

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/marcelodinizsec/goscan-pipeline/internal/model"
	"github.com/marcelodinizsec/goscan-pipeline/internal/ratelimit"
	"github.com/marcelodinizsec/goscan-pipeline/internal/scanner"
)

// Generate emits `count` mock artifacts onto the returned channel,
// simulating an asynchronous event source (upload webhook, message
// queue consumer, filesystem watcher) rather than a static, uniform
// feed. The channel is closed once every artifact has been emitted
// or ctx is cancelled - this is the "orchestração de escaneamento de
// artefatos" entry point.
func Generate(ctx context.Context, count int) <-chan model.Artifact {
	out := make(chan model.Artifact)
	kinds := []model.ArtifactKind{model.KindPE, model.KindELF, model.KindAPK, model.KindScript}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	go func() {
		defer close(out)
		for i := 1; i <= count; i++ {
			a := model.Artifact{
				ID:        i,
				Name:      fmt.Sprintf("artifact-%04d.bin", i),
				Kind:      kinds[rng.Intn(len(kinds))],
				SizeBytes: int64(rng.Intn(50_000_000)),
				Submitted: time.Now(),
			}

			// Jitter emulates a bursty, event-driven arrival process
			// instead of a perfectly uniform loop.
			jitter := time.Duration(rng.Intn(20)) * time.Millisecond
			select {
			case <-time.After(jitter):
			case <-ctx.Done():
				return
			}

			select {
			case out <- a:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}

// ScanStage fans an artifact stream out across `workers` concurrent
// goroutines (competing consumers reading the same channel). Each
// worker optionally waits on a shared rate limiter - this is what
// caps end-to-end throughput independently of how many workers are
// running - then runs the scan engine and emits a ScanResult.
//
// The output channel is closed once every worker has returned,
// coordinated with a sync.WaitGroup: the standard fan-out/fan-in
// shutdown pattern in Go.
func ScanStage(
	ctx context.Context,
	in <-chan model.Artifact,
	workers int,
	engine *scanner.MockEngine,
	limiter *ratelimit.TokenBucket,
) <-chan model.ScanResult {
	out := make(chan model.ScanResult)
	var wg sync.WaitGroup

	worker := func(workerID int) {
		defer wg.Done()
		for {
			select {
			case a, ok := <-in:
				if !ok {
					return
				}
				if limiter != nil {
					if err := limiter.Wait(ctx); err != nil {
						return
					}
				}

				start := time.Now()
				verdict, err := engine.Scan(ctx, a)
				result := model.ScanResult{
					Artifact:   a,
					Verdict:    verdict,
					Engine:     engine.Name,
					StartedAt:  start,
					FinishedAt: time.Now(),
					WorkerID:   workerID,
					Err:        err,
				}

				select {
				case out <- result:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}

	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go worker(w)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
