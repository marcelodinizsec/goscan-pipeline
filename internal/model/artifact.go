// Package model holds the plain data types that flow through the
// scanning pipeline. Keeping them dependency-free makes every other
// package (pipeline, scanner, ratelimit, metrics) easy to test in
// isolation.
package model

import "time"

// ArtifactKind mimics the different object types a real ingestion
// pipeline might see: uploaded binaries, mobile packages, scripts...
type ArtifactKind string

const (
	KindPE     ArtifactKind = "PE"
	KindELF    ArtifactKind = "ELF"
	KindAPK    ArtifactKind = "APK"
	KindScript ArtifactKind = "SCRIPT"
)

// Artifact represents a single unit of work submitted to the
// pipeline - e.g. a file uploaded for analysis, a container layer,
// or a package pulled from a registry.
type Artifact struct {
	ID        int
	Name      string
	Kind      ArtifactKind
	SizeBytes int64
	Submitted time.Time
}

// Verdict is the mock engine's classification for an artifact.
type Verdict string

const (
	VerdictClean      Verdict = "CLEAN"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictMalicious  Verdict = "MALICIOUS"
)

// ScanResult couples an Artifact with the outcome of scanning it,
// plus timing metadata used later for latency/throughput analysis.
type ScanResult struct {
	Artifact   Artifact
	Verdict    Verdict
	Engine     string
	StartedAt  time.Time
	FinishedAt time.Time
	WorkerID   int
	Err        error
}

// Latency returns how long the scan took end-to-end.
func (r ScanResult) Latency() time.Duration {
	return r.FinishedAt.Sub(r.StartedAt)
}
