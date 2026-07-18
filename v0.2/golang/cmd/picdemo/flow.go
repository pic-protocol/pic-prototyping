// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/scenario"
)

// ANSI colors, used only when stdout is a terminal (so pipes / --only-json stay
// clean).
var useColor = stdoutIsTTY()

func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

const (
	cBold   = "1"
	cDim    = "2"
	cRed    = "31"
	cGreen  = "32"
	cYellow = "33"
	cCyan   = "36"
	cActor  = "1;36" // bold cyan
	cReject = "1;31" // bold red
)

// runFlow renders one end-to-end execution flow: authority is minted at the
// origin and narrows hop by hop as real fixture executors continue it, each
// producing a signed PCA, ending with a rogue expansion that PIC rejects. With
// onlyJSON it emits the whole flow as a single JSON document (for jq).
func runFlow(now time.Time, onlyJSON bool) error {
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	res, err := w.Flow(now)
	if err != nil {
		return err
	}

	if onlyJSON {
		printJSON(res)
		return nil
	}

	header("Execution flow — authority created once, narrowing hop by hop")
	fmt.Println(paint(cDim, wrap(res.Description, 92)))
	fmt.Println()
	for i, h := range res.Hops {
		if i > 0 {
			fmt.Println("        " + paint(cDim, "│"))
			fmt.Println("        " + paint(cCyan, "▼"))
		}
		renderHop(h)
	}
	renderRogue(res.Rogue)
	fmt.Printf("\n%s chain verified end to end — authority at tip = %s\n",
		paint(cGreen, "✔"), paint(cGreen, fmt.Sprint(res.TipAuthority)))
	fmt.Println(paint(cDim, "each box's JSON above is the real signed PCA that hop produced; run with --only-json | jq for the machine-readable flow."))
	return nil
}

func renderHop(h scenario.FlowHop) {
	fmt.Printf("%s %s  %s  %s %s\n",
		paint(cCyan, "●"),
		paint(cBold, fmt.Sprintf("hop %d", h.Index)),
		paint(cActor, h.Actor),
		paint(cDim, "—"),
		h.Action)

	line := "    authority: " + paint(cGreen, fmt.Sprint(h.Authority))
	if len(h.Dropped) > 0 {
		line += "   " + paint(cRed, "dropped: "+strings.Join(h.Dropped, ", "))
	}
	fmt.Println(line)

	if h.PreviousHash != "" {
		fmt.Println("    " + paint(cDim, fmt.Sprintf("counter %d   prevHash %s", h.LineageCounter, shortHash(h.PreviousHash))))
	} else {
		fmt.Println("    " + paint(cDim, fmt.Sprintf("counter %d   origin (no predecessor)", h.LineageCounter)))
	}
	fmt.Println("    " + paint(cDim, fmt.Sprintf("generates PCA%d (signed) ▾", h.Index)))
	printIndentedJSON(h.Generates, "      ")
}

func renderRogue(r *scenario.RogueAttempt) {
	if r == nil {
		return
	}
	fmt.Println("        " + paint(cDim, "│"))
	fmt.Println("        " + paint(cReject, "▼"))
	fmt.Printf("%s %s  %s  %s tries to re-add dropped authority\n",
		paint(cReject, "✗"), paint(cBold, "hop 5 (rogue)"), paint(cActor, r.Actor), paint(cDim, "—"))
	fmt.Printf("    tried: %s   %s\n", paint(cReject, fmt.Sprint(r.Tried)),
		paint(cReject, boolStr(r.Rejected, "→ REJECTED (non-expansion)", "→ accepted (BUG!)")))
	fmt.Println("    " + paint(cDim, "reason: "+r.Reason))
}

func printIndentedJSON(v any, prefix string) {
	b, err := json.MarshalIndent(v, prefix, "  ")
	if err != nil {
		fmt.Println(prefix + "(marshal error)")
		return
	}
	fmt.Println(prefix + string(b))
}

func shortHash(h string) string {
	if len(h) <= 21 {
		return h
	}
	return h[:21] + "…"
}

func boolStr(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// wrap soft-wraps s to width columns for the intro line.
func wrap(s string, width int) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, wd := range words {
		if col+len(wd)+1 > width && col > 0 {
			b.WriteByte('\n')
			col = 0
		} else if i > 0 {
			b.WriteByte(' ')
			col++
		}
		b.WriteString(wd)
		col += len(wd)
	}
	return b.String()
}
