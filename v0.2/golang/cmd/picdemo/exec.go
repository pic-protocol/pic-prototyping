// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
	"github.com/pic-protocol/pic-prototyping/v0.2/golang/scenario"
)

// This file implements `picdemo exec`: an interactive viewer of a Sandboxed
// Execution. It shows PIC carrying PIC — the outer ENFORCE lineage carrying an
// inner Multi-Lineage Execution — as a compact hop diagram, lets you drill into
// one carried lineage (or the outer lineage, or all), and inspect every PCA.
// The guardrail is on by default; --no-guardrail shows the inner lineages alone.

// execOpts are the exec-command options, parsed from the positional args.
type execOpts struct {
	guardrail bool   // default true; --no-guardrail turns it off
	pca       bool   // --pca: print the full signed PCA JSON per hop
	lineage   string // "", "all", "outer", or a carried-lineage label (A, B, ...)
}

// runExec is the `exec` command entry point.
func runExec(now time.Time, o opts) error {
	eo := execOpts{guardrail: true}
	for i := 0; i < len(o.selectors); i++ {
		a := o.selectors[i]
		switch {
		case a == "--no-guardrail":
			eo.guardrail = false
		case a == "--guardrail", a == "-g":
			eo.guardrail = true
		case a == "--pca":
			eo.pca = true
		case a == "--lineage" || a == "-l":
			if i+1 < len(o.selectors) {
				i++
				eo.lineage = o.selectors[i]
			}
		case strings.HasPrefix(a, "--lineage="):
			eo.lineage = strings.TrimPrefix(a, "--lineage=")
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("exec: unknown flag %q (use --lineage <A|B|outer|all>, --pca, --no-guardrail)", a)
		default:
			eo.lineage = a // bare lineage selector: `picdemo exec A`
		}
	}

	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	res, err := w.Guarded(now)
	if err != nil {
		return err
	}
	c := res.Permit // the permit crossing carries the full outer + carried lineages

	// A carried lineage: its label, chain, and (from the trace) grant/scopes.
	type lin struct {
		label     string
		chain     []*pic.PCA
		grant     string
		scopes    []string
		authority []string
		origin    string
	}
	var carried []lin
	for _, p := range c.MLE.Participants {
		l := lin{label: p.Label, chain: p.Chain, origin: p.Chain[0].Issuer}
		for _, tp := range c.Trace.CarriedLineages {
			if tp.Label == p.Label {
				l.grant, l.scopes, l.authority = tp.GrantID, tp.Scopes, tp.Authority
			}
		}
		carried = append(carried, l)
	}
	findCarried := func(label string) *lin {
		for i := range carried {
			if strings.EqualFold(carried[i].label, label) {
				return &carried[i]
			}
		}
		return nil
	}
	labelList := func() string {
		var s []string
		for _, l := range carried {
			s = append(s, l.label)
		}
		return strings.Join(s, ", ")
	}

	// --only-json: emit the structured execution for jq.
	if o.onlyJSON {
		out := map[string]any{
			"mode":      map[bool]string{true: "sandboxed", false: "inner-only (--no-guardrail)"}[eo.guardrail],
			"selection": defaultStr(eo.lineage, "compact"),
		}
		if eo.guardrail {
			out["outerChain"] = c.OuterChain
			out["decision"] = c.Trace.Decision
		}
		var cl []map[string]any
		for _, l := range carried {
			cl = append(cl, map[string]any{"label": l.label, "grant": l.grant,
				"scopes": l.scopes, "authority": l.authority, "chain": l.chain})
		}
		out["carriedLineages"] = cl
		printJSON(out)
		return nil
	}

	// --no-guardrail: show the inner Multi-Lineage Execution alone (debug).
	if !eo.guardrail {
		header("Execution (--no-guardrail) — inner Multi-Lineage Execution, no Sandboxed Execution")
		fmt.Println(paint(cDim, wrap("Debug view: the carried lineages as they would execute without the outer ENFORCE lineage. No guardrail hop, no enforced acceptance — use this to inspect the participants alone.", 96)))
		fmt.Println()
		if eo.lineage != "" && !strings.EqualFold(eo.lineage, "all") {
			l := findCarried(eo.lineage)
			if l == nil {
				return fmt.Errorf("exec: no carried lineage %q (have %s)", eo.lineage, labelList())
			}
			renderLineageChain("carried lineage "+l.label, l.origin, l.chain, l.grant, l.scopes, eo.pca)
			return nil
		}
		for i, l := range carried {
			if i > 0 {
				fmt.Println()
			}
			renderLineageChain("carried lineage "+l.label, l.origin, l.chain, l.grant, l.scopes, eo.pca)
		}
		fmt.Println(paint(cDim, "\nre-enable the guardrail: picdemo exec        (Sandboxed Execution, on by default)"))
		return nil
	}

	// Drill-down selections.
	switch {
	case strings.EqualFold(eo.lineage, "outer"):
		header("Outer ENFORCE lineage (the Sandboxed Execution)")
		renderOuterChain(c.OuterChain, c.Trace, eo.pca)
		return nil
	case strings.EqualFold(eo.lineage, "all"):
		header("Sandboxed Execution — every lineage")
		renderOuterChain(c.OuterChain, c.Trace, eo.pca)
		for _, l := range carried {
			fmt.Println()
			renderLineageChain("carried lineage "+l.label, l.origin, l.chain, l.grant, l.scopes, eo.pca)
		}
		return nil
	case eo.lineage != "":
		l := findCarried(eo.lineage)
		if l == nil {
			return fmt.Errorf("exec: no carried lineage %q (have %s, or 'outer'/'all')", eo.lineage, labelList())
		}
		header("Carried lineage " + l.label)
		renderLineageChain("carried lineage "+l.label, l.origin, l.chain, l.grant, l.scopes, eo.pca)
		return nil
	}

	// Default: the compact Sandboxed Execution diagram.
	renderExecCompact(res)
	return nil
}

// renderExecCompact draws the Sandboxed Execution as the spec does: the outer
// ENFORCE lineage hops, each guardrail hop showing its enforcementResult and the
// carried Multi-Lineage Execution by lineage name.
func renderExecCompact(res *scenario.GuardedResult) {
	c := res.Permit
	header("Sandboxed Execution — PIC carrying PIC")
	fmt.Println(paint(cDim, wrap("An outer PIC lineage with authority { ENFORCE } carries the inner Multi-Lineage Execution. Each guardrail is the next ordinary executor of that outer lineage; its signed outer PCA is the decision.", 96)))
	fmt.Println()

	fmt.Printf("%s  %s\n", paint(cBold, "SANDBOXED EXECUTION"),
		paint(cDim, "· outer PIC lineage · authority { ENFORCE }"))

	// PCA0-G origin.
	fmt.Printf("  %s  %s %s\n", paint(cCyan, "PCA0-G"), paint(cDim, "origin — authorized sandbox origin"),
		paint(cActor, res.Origin.Issuer))
	fmt.Println("      " + paint(cDim, "│ PoR"))
	fmt.Println("      " + paint(cCyan, "▼"))

	// PCA1-G guardrail hop.
	fmt.Printf("  %s  %s %s   →  %s   →  %s\n", paint(cCyan, "PCA1-G"),
		paint(cDim, "guardrail"), paint(cActor, c.Trace.GuardrailExecutor),
		decision(c.Trace.Decision.Effect), c.MLE.Destination)
	fmt.Println("      " + paint(cDim, "carries Multi-Lineage Execution:"))
	for i, p := range c.MLE.Participants {
		branch := "├─"
		if i == len(c.MLE.Participants)-1 {
			branch = "└─"
		}
		var auth, scopes []string
		for _, tp := range c.Trace.CarriedLineages {
			if tp.Label == p.Label {
				auth, scopes = tp.Authority, tp.Scopes
			}
		}
		fmt.Printf("        %s %s  %s  %s  %s\n",
			paint(cCyan, branch), paint(cBold, p.Label),
			paint(cGreen, fmt.Sprint(auth)),
			paint(cYellow, fmt.Sprint(scopes)),
			paint(cDim, fmt.Sprintf("origin %s · %d PCAs", short(p.Chain[0].Issuer), len(p.Chain))))
	}

	fmt.Printf("\n%s outer PCA1-G is the guardrail decision — no envelope, no second signature.\n", paint(cGreen, "✔"))
	fmt.Println(paint(cDim, "\nexplore:"))
	fmt.Println(paint(cDim, "  picdemo exec A                 one carried lineage (or B)"))
	fmt.Println(paint(cDim, "  picdemo exec outer             the outer ENFORCE lineage"))
	fmt.Println(paint(cDim, "  picdemo exec all --pca         every lineage, full signed PCAs"))
	fmt.Println(paint(cDim, "  picdemo exec --no-guardrail    inner lineages only (debug)"))
}

// renderOuterChain renders the outer ENFORCE lineage hop by hop.
func renderOuterChain(chain []*pic.PCA, t *pic.EnforcementTrace, withPCA bool) {
	fmt.Println(paint(cDim, "authority { ENFORCE } continues one predecessor per hop; each guardrail signs its own outer PCA"))
	fmt.Println()
	for i, p := range chain {
		if i > 0 {
			fmt.Println("      " + paint(cDim, "│ PoR"))
			fmt.Println("      " + paint(cCyan, "▼"))
		}
		name := fmt.Sprintf("PCA%d-G", p.LineageCounter)
		if p.IsOrigin() {
			fmt.Printf("  %s  %s  %s  %s\n", paint(cCyan, name), paint(cBold, "origin"),
				paint(cGreen, fmt.Sprint(p.Invariants.Operations)),
				paint(cDim, "sandbox origin "+short(p.Issuer)))
		} else {
			por := p.ProofOfRelationship
			verd := ""
			if por.Request.EnforcementResult != "" {
				verd = "  " + decision(por.Request.EnforcementResult)
			}
			fmt.Printf("  %s  %s  %s%s\n", paint(cCyan, name),
				paint(cGreen, fmt.Sprint(p.Invariants.Operations)),
				paint(cDim, "guardrail "+short(por.Executor)), verd)
			fmt.Printf("      %s\n", paint(cDim, fmt.Sprintf("prevHash %s   request.operation %s", shortHash(por.PreviousPcaHash), por.Request.Operation)))
			if por.Request.MultiLineageDigest != "" {
				fmt.Printf("      %s\n", paint(cDim, "multiLineageDigest "+shortHash(por.Request.MultiLineageDigest)))
			}
			if p.MultiLineage != nil {
				var names []string
				for _, cl := range p.MultiLineage.CarriedLineages {
					names = append(names, cl.Label)
				}
				fmt.Printf("      %s\n", paint(cDim, fmt.Sprintf("carries carriedLineages [%s]", strings.Join(names, ", "))))
			}
		}
		if withPCA {
			fmt.Println("      " + paint(cDim, "signed PCA ▾"))
			printIndentedJSON(p, "        ")
		}
	}
}

// renderLineageChain renders one carried (inner) lineage hop by hop.
func renderLineageChain(title, origin string, chain []*pic.PCA, grant string, scopes []string, withPCA bool) {
	fmt.Printf("%s %s  %s\n", paint(cCyan, "●"), paint(cBold, title),
		paint(cDim, fmt.Sprintf("origin %s · %d PCAs", origin, len(chain))))
	if grant != "" || len(scopes) > 0 {
		fmt.Printf("  %s\n", paint(cDim, fmt.Sprintf("grant %s → scopes %v (enforcement input, not self-asserted)", grant, scopes)))
	}
	fmt.Println()
	for i, p := range chain {
		if i > 0 {
			fmt.Println("      " + paint(cDim, "│ PoR"))
			fmt.Println("      " + paint(cCyan, "▼"))
		}
		name := fmt.Sprintf("PCA%d", p.LineageCounter)
		if p.IsOrigin() {
			fmt.Printf("  %s  %s  %s  %s\n", paint(cCyan, name), paint(cBold, "origin"),
				paint(cGreen, fmt.Sprint(p.Invariants.Operations)),
				paint(cDim, "issuer "+short(p.Issuer)))
		} else {
			por := p.ProofOfRelationship
			fmt.Printf("  %s  %s  %s\n", paint(cCyan, name),
				paint(cGreen, fmt.Sprint(p.Invariants.Operations)),
				paint(cDim, "executor "+short(por.Executor)))
			fmt.Printf("      %s\n", paint(cDim, fmt.Sprintf("prevHash %s   request %s %s",
				shortHash(por.PreviousPcaHash), por.Request.Operation, por.Request.Target)))
		}
		if withPCA {
			fmt.Println("      " + paint(cDim, "signed PCA ▾"))
			printIndentedJSON(p, "        ")
		}
	}
}

// short trims a DID to its last label for compact lines.
func short(did string) string {
	if i := strings.LastIndexByte(did, ':'); i >= 0 && i+1 < len(did) {
		did = did[i+1:]
	}
	if j := strings.IndexByte(did, '#'); j >= 0 {
		did = did[:j]
	}
	return did
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
