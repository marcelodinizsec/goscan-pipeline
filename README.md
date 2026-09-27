# goscan-pipeline

Theoretical + practical study of **event-driven concurrent pipelines in Go**,
using a **mock artifact scanner** as the use case (the kind of component that
sits behind malware detection systems, sandboxes, and VirusTotal-style
scanning services).

The goal is not to build a real scanner, but to isolate and exercise, in
compilable and testable code, the concurrency mechanisms that underpin this
type of system in production:

- event-driven pipelines, not fixed batches;
- artifact scan orchestration via *fan-out* to a worker pool;
- explicit **throughput** control, independent of per-item **latency**
  control.

## 1. Theoretical background

### 1.1 Goroutines and channels (the CSP model)

Go implements a variant of the **CSP (Communicating Sequential Processes)**
model: instead of protecting shared memory with locks, the language
recommends "share memory by communicating" — that is, passing data between
goroutines through `channels`. Goroutines are cheap (a few KB of stack, grown
dynamically, scheduled M:N by the runtime on top of OS threads), which makes
it feasible to have thousands of them active at once — something that
wouldn't be reasonable with OS threads.

### 1.2 The *Pipeline* pattern

A pipeline in Go is a series of *stages* connected by channels, where each
stage:

1. receives values from an upstream input channel;
2. does some processing;
3. sends values to a downstream output channel.

In this project the stages are: `Generate` → `ScanStage` → metrics
aggregation in `main`.

### 1.3 *Fan-out / Fan-in*

When a stage is expensive (here, the "scan"), that stage is replicated across
N goroutines reading from the **same** input channel (*fan-out* — concurrent
consumers competing for the same items) and writing to the **same** output
channel (*fan-in*). Correctly closing the output channel depends on a
`sync.WaitGroup`: it's only closed once every worker has finished, never
before.

### 1.4 *Worker Pool*

The number of scan goroutines is fixed and configurable (`--workers`), not
one goroutine per artifact. This caps the actual parallelism at what the
CPU/engine can sustain and prevents a spike in artifacts from spawning
thousands of goroutines competing for resources.

### 1.5 `context.Context` and cancellation

Every pipeline stage watches `ctx.Done()` in a `select`. This enables
**cooperative cancellation**: a global timeout or a Ctrl+C (`SIGINT`, via
`signal.NotifyContext`) propagates to the generator, the workers, and the
rate limiter, preventing leaked goroutines when the pipeline is interrupted.

### 1.6 Backpressure

The channels used here are **unbuffered** (`make(chan T)`) at the fan-out/
fan-in points: a `send` blocks until there's a matching `receive`. This
propagates backpressure naturally — if the workers are saturated, the
artifact generator automatically slows down, with no need for an unbounded
queue growing in memory.

### 1.7 Throughput control vs. latency control

This is the central point of the study, and the two are **not** the same
thing:

- **Latency** is how long a single artifact takes to be scanned (here,
  simulated by `MinLatency`/`MaxLatency` in `MockEngine`).
- **Throughput** is how many artifacts per second the system processes as a
  whole — controlled here by a **token bucket** (`internal/ratelimit`),
  hand-implemented (without `golang.org/x/time/rate`) on purpose, to make the
  refill mechanism and the blocking token acquisition explicit.

Increasing `--workers` increases parallelism (more scans running at once),
but doesn't change the latency of each individual scan. Lowering `--rate`
caps how many scans start per second, regardless of how many workers exist.
The two experiments in section 4 make this difference visible in actual
numbers.

## 2. Architecture

```
                    ┌──────────────┐
   (event/jitter)   │   Generate   │  emits Artifact at irregular intervals
                    └──────┬───────┘
                           │ chan Artifact (unbuffered)
                           ▼
          ┌───────────────────────────────────┐
          │            ScanStage               │
          │  ┌─────────┐ ┌─────────┐  ┌──────┐ │   fan-out: N workers
          │  │worker 1 │ │worker 2 │..│workerN│ │   competing for the same
          │  └────┬────┘ └────┬────┘  └───┬──┘ │   input channel;
          │       │ TokenBucket.Wait()     │    │   each worker calls
          │       ▼           ▼            ▼    │   engine.Scan(ctx, artifact)
          └───────────────────────────────────┘
                           │ chan ScanResult (fan-in)
                           ▼
                 ┌──────────────────┐
                 │ metrics.Collector │  latency (min/avg/p95/max),
                 └──────────────────┘  throughput, verdict counts
```

## 3. How to run

Prerequisite: Go 1.22+.

```bash
git clone https://github.com/<your-username>/goscan-pipeline.git
cd goscan-pipeline
go build ./...
go run ./cmd/scanner --artifacts 200 --workers 8 --rate 50 --burst 10
```

Main flags:

| Flag              | Description                                          | Default |
|-------------------|-------------------------------------------------------|---------|
| `--artifacts`     | number of mock artifacts to submit                     | 200     |
| `--workers`       | concurrent goroutines in the scan fan-out               | 8       |
| `--rate`          | max throughput in scans/sec (0 = unlimited)             | 50      |
| `--burst`         | token bucket burst capacity                             | 10      |
| `--min-latency-ms`| minimum simulated latency per scan                      | 20      |
| `--max-latency-ms`| maximum simulated latency per scan                      | 200     |
| `--timeout`       | overall pipeline timeout                                | 60s     |
| `--quiet`         | suppress the per-artifact log line                      | false   |

Tests and concurrency-correctness checks (data race detector):

```bash
go vet ./...
go test ./...          # (see section 5 — tests still to be written)
go run -race ./cmd/scanner --artifacts 100 --workers 8
```

## 4. Suggested experiments (the hands-on part of the study)

1. **Throughput vs. workers**: set `--rate 0` (unlimited) and vary
   `--workers` across 1, 4, 16, 64. Watch the final throughput — at some
   point it stops growing because the scan "engine" (simulated latency)
   becomes the bottleneck, not the number of workers.
2. **Throughput vs. rate limit**: fix `--workers 32` and vary `--rate`
   across 10, 50, 200 and 0. Notice that the measured throughput converges
   to the `--rate` value, not to what the workers could sustain on their own.
3. **Burst effect**: with a low `--rate`, increase `--burst` and observe
   longer initial bursts before throughput settles at the configured value.
4. **Cancellation**: run with `--timeout 2s` and `--artifacts 100000` and
   confirm the process exits shortly after the timeout, without hanging —
   evidence that cancellation via `context` is propagating correctly through
   every stage.
5. **p95 latency under load**: increase `--max-latency-ms` while keeping
   `--rate` fixed and observe how p95 latency grows even with stable
   throughput — this illustrates why detection SLOs are usually stated in
   terms of p95/p99, not average.

## 5. Evolution roadmap

Ideas for continuing the study, in increasing order of complexity:

- [ ] Unit tests per package (`ratelimit`, `pipeline`, `metrics`) with
      `go test -race`.
- [ ] Swap `MockEngine` for a real adapter: YARA (via `go-yara` or by
      shelling out to the `yara` binary), ClamAV (`clamd` socket), or
      hashing + a local allowlist/denylist lookup.
- [ ] Replace the in-memory generator with a real event source: a filesystem
      watcher (`fsnotify`), a queue (NATS, Kafka, SQS), or an HTTP webhook.
- [ ] Export metrics to Prometheus (`/metrics`) instead of just printing a
      final summary — enables watching p95/throughput in real time with
      Grafana.
- [ ] Prioritization: a priority queue (e.g., artifacts from untrusted
      sources jump the line) instead of plain FIFO.
- [ ] Per-engine circuit breaker: if a scan engine starts failing or slowing
      down too much, temporarily stop routing traffic to it.
- [ ] Persist results (SQLite/Postgres) to allow historical queries of
      verdicts per artifact.
- [ ] Finer-grained graceful shutdown: drain what's already in flight before
      exiting, instead of cancelling immediately via `context`.

## 6. References for the theoretical background

- Rob Pike, *"Go Concurrency Patterns"* (Google I/O 2012).
- Go Blog: *"Go Concurrency Patterns: Pipelines and cancellation"*.
- Go Blog: *"Rate Limiting"* (the conceptual basis for the token bucket used
  here).
- Effective Go — *Concurrency* section.
- stdlib documentation for `context`, `sync`, and `sync/atomic`.
