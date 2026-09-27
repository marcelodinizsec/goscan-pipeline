// Command scanner runs a mock, high-concurrency artifact scanning
// pipeline. It exists as a study project for Go's concurrency
// primitives (goroutines, channels, context, select) applied to a
// realistic problem shape: an event-driven ingestion pipeline with
// worker-pool fan-out and explicit throughput control.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/marcelodinizsec/goscan-pipeline/internal/metrics"
	"github.com/marcelodinizsec/goscan-pipeline/internal/pipeline"
	"github.com/marcelodinizsec/goscan-pipeline/internal/ratelimit"
	"github.com/marcelodinizsec/goscan-pipeline/internal/scanner"
)

func main() {
	var (
		numArtifacts = flag.Int("artifacts", 200, "number of mock artifacts to submit")
		numWorkers   = flag.Int("workers", 8, "number of concurrent scan workers")
		ratePerSec   = flag.Float64("rate", 50, "max scans/sec throughput cap (0 = unlimited)")
		burst        = flag.Int("burst", 10, "token bucket burst size")
		minLatencyMs = flag.Int("min-latency-ms", 20, "minimum simulated scan latency")
		maxLatencyMs = flag.Int("max-latency-ms", 200, "maximum simulated scan latency")
		timeout      = flag.Duration("timeout", 60*time.Second, "overall pipeline timeout")
		quiet        = flag.Bool("quiet", false, "suppress per-artifact log lines")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	engine := scanner.NewMockEngine(
		"mock-av-v1",
		time.Duration(*minLatencyMs)*time.Millisecond,
		time.Duration(*maxLatencyMs)*time.Millisecond,
		0.05, // 5% malicious
		0.15, // 15% suspicious
	)

	var limiter *ratelimit.TokenBucket
	if *ratePerSec > 0 {
		limiter = ratelimit.New(*ratePerSec, *burst)
	}

	log.Printf(
		"starting pipeline: artifacts=%d workers=%d rate=%.1f/s burst=%d latency=[%d,%d]ms",
		*numArtifacts, *numWorkers, *ratePerSec, *burst, *minLatencyMs, *maxLatencyMs,
	)

	artifacts := pipeline.Generate(ctx, *numArtifacts)
	results := pipeline.ScanStage(ctx, artifacts, *numWorkers, engine, limiter)

	collector := metrics.NewCollector()
	start := time.Now()
	for r := range results {
		collector.Observe(r)
		if !*quiet && r.Err == nil {
			fmt.Printf("[worker %02d] %-20s kind=%-6s verdict=%-10s latency=%v\n",
				r.WorkerID, r.Artifact.Name, r.Artifact.Kind, r.Verdict, r.Latency())
		}
	}
	wall := time.Since(start)

	sum := collector.Summary()
	fmt.Println("\n--- pipeline summary ---")
	fmt.Printf("processed:   %d (errors: %d)\n", sum.Count, sum.Errors)
	fmt.Printf("verdicts:    %v\n", sum.Verdicts)
	fmt.Printf("latency:     min=%v avg=%v p95=%v max=%v\n",
		sum.MinLatency, sum.AvgLatency, sum.P95Latency, sum.MaxLatency)
	fmt.Printf("throughput:  %.2f artifacts/sec (wall clock: %v)\n", sum.Throughput, wall)
}
