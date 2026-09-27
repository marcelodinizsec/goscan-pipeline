// Package metrics accumulates ScanResults and derives the
// latency/throughput statistics used to evaluate the pipeline under
// different worker-count / rate-limit configurations.
package metrics

import (
	"sort"
	"sync"
	"time"

	"github.com/marcelodinizsec/goscan-pipeline/internal/model"
)

// Collector is safe for concurrent use: the aggregator (main
// goroutine) calls Observe once per ScanResult as they arrive from
// the fan-in channel.
type Collector struct {
	mu        sync.Mutex
	latencies []time.Duration
	verdicts  map[model.Verdict]int
	errors    int
	firstAt   time.Time
	lastAt    time.Time
}

func NewCollector() *Collector {
	return &Collector{verdicts: make(map[model.Verdict]int)}
}

func (c *Collector) Observe(r model.ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if r.Err != nil {
		c.errors++
		return
	}
	c.latencies = append(c.latencies, r.Latency())
	c.verdicts[r.Verdict]++
	if c.firstAt.IsZero() || r.StartedAt.Before(c.firstAt) {
		c.firstAt = r.StartedAt
	}
	if r.FinishedAt.After(c.lastAt) {
		c.lastAt = r.FinishedAt
	}
}

// Summary is a point-in-time snapshot of collected statistics.
type Summary struct {
	Count        int
	Errors       int
	Verdicts     map[model.Verdict]int
	MinLatency   time.Duration
	MaxLatency   time.Duration
	AvgLatency   time.Duration
	P95Latency   time.Duration
	Throughput   float64 // artifacts/sec, wall-clock
	WallDuration time.Duration
}

func (c *Collector) Summary() Summary {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := len(c.latencies)
	s := Summary{Count: n, Errors: c.errors, Verdicts: map[model.Verdict]int{}}
	for k, v := range c.verdicts {
		s.Verdicts[k] = v
	}
	if n == 0 {
		return s
	}

	sorted := make([]time.Duration, n)
	copy(sorted, c.latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	s.MinLatency = sorted[0]
	s.MaxLatency = sorted[n-1]
	s.AvgLatency = total / time.Duration(n)

	p95Idx := int(float64(n) * 0.95)
	if p95Idx >= n {
		p95Idx = n - 1
	}
	s.P95Latency = sorted[p95Idx]

	s.WallDuration = c.lastAt.Sub(c.firstAt)
	if s.WallDuration > 0 {
		s.Throughput = float64(n) / s.WallDuration.Seconds()
	}
	return s
}
