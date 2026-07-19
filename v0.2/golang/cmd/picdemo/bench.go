// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
	"github.com/pic-protocol/pic-prototyping/v0.2/golang/scenario"
)

// pcaSizes holds the serialized (compact JSON) byte sizes of representative
// artifacts, to show the on-the-wire weight of a PCA.
type pcaSizes struct{ pca0, successor, envelope int }

// jsonLen is the byte length of the compact JSON serialization of v.
func jsonLen(v any) int { b, _ := json.Marshal(v); return len(b) }

// sizeStr renders a byte count as "1,280 B (1.25 KB)".
func sizeStr(n int) string {
	return fmt.Sprintf("%s B (%.2f KB)", commas(int64(n)), float64(n)/1024)
}

// benchRow is one measured operation.
type benchRow struct {
	Name      string  `json:"name"`
	Iters     int     `json:"iters"`
	NsPerOp   float64 `json:"nsPerOp"`
	OpsPerSec float64 `json:"opsPerSec"`
}

// runBench measures the key PIC operations on the real fixtures and prints a
// colored table (or a JSON array with --only-json). It is a self-contained
// harness, separate from `go test -bench`, for a readable at-a-glance report.
func runBench(now time.Time, onlyJSON bool) error {
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	reg := w.Set.Registry
	inv := pic.Invariants{Operations: []string{"read:/user/*"}}
	req := pic.Request{Operation: "read", Target: "/user/file", SecurityDomain: "tenant-42"}

	// Shared setup, done once (not timed).
	pca0, err := pic.MintPCA0(w.Set.Identity("alice"), inv, "", now)
	if err != nil {
		return err
	}
	prover := pic.NewProver(w.Set.Identity("gateway"), w.Set.Attestation("gateway"))
	pca1, err := prover.Continue(pca0, inv, req, now)
	if err != nil {
		return err
	}
	chain, err := w.BuildChain(64, now)
	if err != nil {
		return err
	}
	through := len(chain) - 1 - 8
	snap, err := pic.IssueSnapshot(w.Set.Identity("snapshot-issuer"), reg, chain, through, now)
	if err != nil {
		return err
	}
	tail := chain[through:]

	env, err := pic.WrapEnvelope(w.Set.Identity("gateway"), pca0, pca1)
	if err != nil {
		return err
	}
	sizes := pcaSizes{pca0: jsonLen(pca0), successor: jsonLen(pca1), envelope: jsonLen(env)}

	cases := []struct {
		name string
		fn   func()
	}{
		{"sign PCA0 (Ed25519)", func() { _, _ = pic.MintPCA0(w.Set.Identity("alice"), inv, "", now) }},
		{"prove hop", func() { _, _ = prover.Continue(pca0, inv, req, now) }},
		{"verify hop", func() { _ = pic.NewVerifier(reg, nil).VerifyHop(pca1, pca0, now, false) }},
		{"digest (SHA-256)", func() { _, _ = pca1.Digest() }},
		{"verify full chain (64 hops)", func() { _, _ = pic.NewVerifier(reg, nil).VerifyFullChain(chain, now) }},
		{"verify from snapshot (tail 8)", func() { _, _ = pic.NewVerifier(reg, nil).VerifyFromSnapshot(snap, tail, now) }},
		{"authority-mixing (scenario)", func() { _, _ = w.AuthorityMixing(now) }},
	}

	rows := make([]benchRow, len(cases))
	for i, c := range cases {
		iters, per := measure(c.fn)
		ns := float64(per.Nanoseconds())
		rows[i] = benchRow{Name: c.name, Iters: iters, NsPerOp: ns, OpsPerSec: 1e9 / ns}
	}

	if onlyJSON {
		printJSON(rows)
		return nil
	}
	renderBench(rows, sizes)
	return nil
}

// measure runs fn until at least ~200ms have elapsed and returns the iteration
// count and the average duration per call.
func measure(fn func()) (int, time.Duration) {
	fn() // warm up
	iters := 1
	for {
		start := time.Now()
		for i := 0; i < iters; i++ {
			fn()
		}
		elapsed := time.Since(start)
		if elapsed >= 200*time.Millisecond || iters >= 1<<22 {
			return iters, elapsed / time.Duration(iters)
		}
		iters *= 2
	}
}

func renderBench(rows []benchRow, sizes pcaSizes) {
	header("Micro-benchmarks on the real fixtures")
	fmt.Println(paint(cDim, fmt.Sprintf("%s/%s · %d CPU · %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())))
	fmt.Println()

	maxNs := 0.0
	for _, r := range rows {
		if r.NsPerOp > maxNs {
			maxNs = r.NsPerOp
		}
	}

	fmt.Printf("  %s %s %s %s\n",
		pad(paint(cBold, "operation"), 32),
		padLeft(paint(cBold, "latency"), 11),
		padLeft(paint(cBold, "throughput"), 14),
		paint(cBold, "relative"))
	fmt.Println("  " + paint(cDim, strings.Repeat("─", 74)))

	for _, r := range rows {
		lat := fmtDur(time.Duration(int64(r.NsPerOp)))
		thr := commas(int64(r.OpsPerSec)) + "/s"
		bar := latencyBar(r.NsPerOp, maxNs)
		fmt.Printf("  %s %s %s %s\n",
			pad(paint(cCyan, r.Name), 32),
			padLeft(paint(cYellow, lat), 11),
			padLeft(paint(cGreen, thr), 14),
			bar)
	}
	fmt.Println("  " + paint(cDim, strings.Repeat("─", 74)))

	// The headline: snapshot vs full-chain.
	var full, snap float64
	for _, r := range rows {
		if strings.HasPrefix(r.Name, "verify full chain") {
			full = r.NsPerOp
		}
		if strings.HasPrefix(r.Name, "verify from snapshot") {
			snap = r.NsPerOp
		}
	}
	if full > 0 && snap > 0 {
		fmt.Printf("  %s snapshot verify is %s than full-chain — the O(hops since snapshot) win (§5.2)\n",
			paint(cGreen, "▶"), paint("1;32", fmt.Sprintf("%.1f× faster", full/snap)))
	}

	// Per-hop cost: one executor receives PCA[n], verifies it, and emits PCA[n+1].
	var verifyNs, proveNs float64
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r.Name, "verify hop"):
			verifyNs = r.NsPerOp
		case strings.HasPrefix(r.Name, "prove hop"):
			proveNs = r.NsPerOp
		}
	}
	if verifyNs > 0 && proveNs > 0 {
		total := verifyNs + proveNs
		fmt.Println()
		fmt.Println("  " + paint(cBold, "per hop") + paint(cDim, "  (incremental profile: receive PCA[n] → verify → emit PCA[n+1])"))
		fmt.Printf("    %s %s\n", pad("verify received (n)", 22), padLeft(paint(cYellow, fmtDur(dur(verifyNs))), 11))
		fmt.Printf("    %s %s\n", pad("prove / emit (n+1)", 22), padLeft(paint(cYellow, fmtDur(dur(proveNs))), 11))
		fmt.Println("    " + paint(cDim, strings.Repeat("─", 34)))
		fmt.Printf("    %s %s   %s\n",
			pad(paint(cBold, "total per hop"), 22),
			padLeft(paint("1;33", fmtDur(dur(total))), 11),
			paint(cGreen, "~"+commas(int64(1e9/total))+" hops/s"))
	}

	fmt.Println()
	fmt.Printf("  %s  PCA0 %s · successor %s · envelope %s\n",
		paint(cBold, "serialized size"),
		paint(cYellow, sizeStr(sizes.pca0)),
		paint(cYellow, sizeStr(sizes.successor)),
		paint(cYellow, sizeStr(sizes.envelope)))

	fmt.Println(paint(cDim, "  (illustrative visual demo, not rigorous — for real numbers run `task v0-2-go-bench` (go test))"))
}

// dur converts a nanosecond count to a time.Duration.
func dur(ns float64) time.Duration { return time.Duration(int64(ns)) }

// latencyBar draws a bar proportional to latency, colored by speed tier.
func latencyBar(ns, maxNs float64) string {
	const width = 26
	n := 1
	if maxNs > 0 {
		n = int(ns / maxNs * width)
	}
	if n < 1 {
		n = 1
	}
	color := cGreen
	switch {
	case ns > 0.5*maxNs:
		color = cRed
	case ns > 0.15*maxNs:
		color = cYellow
	}
	return paint(color, strings.Repeat("█", n))
}

func fmtDur(d time.Duration) string {
	ns := d.Nanoseconds()
	switch {
	case ns < 1000:
		return fmt.Sprintf("%d ns", ns)
	case ns < 1_000_000:
		return fmt.Sprintf("%.1f µs", float64(ns)/1e3)
	default:
		return fmt.Sprintf("%.2f ms", float64(ns)/1e6)
	}
}

// commas formats an integer with thousands separators.
func commas(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// pad / padLeft account for ANSI escape codes when computing visible width.
func pad(s string, w int) string {
	n := w - visibleLen(s)
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}

func padLeft(s string, w int) string {
	n := w - visibleLen(s)
	if n <= 0 {
		return s
	}
	return strings.Repeat(" ", n) + s
}

func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case !inEsc:
			n++
		}
	}
	return n
}
