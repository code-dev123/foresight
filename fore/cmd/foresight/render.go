package main

import (
	"fmt"
	"io"
	"strings"

	"foresight/pkg/types"
)

// renderPretty writes a human-readable summary of the snapshot.
// Kept deliberately simple — no colors, no heavy UI libraries. We'll add
// them once the CLI output format stabilizes.
func renderPretty(w io.Writer, s *types.ClusterSnapshot) error {
	fmt.Fprintln(w, bold("FORESIGHT IMPACT ANALYSIS"))
	fmt.Fprintln(w, separator())

	// Metadata line
	fmt.Fprintf(w, "%s %s %s  |  collection time: %dms\n",
		label("Generated:"), s.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"),
		maybeContext(s.Metadata.ClusterContext), s.Metadata.CollectionTimeMS)
	fmt.Fprintln(w)

	// Proposed change
	fmt.Fprintln(w, bold("Proposed change"))
	fmt.Fprintf(w, "  %-12s %s\n", "Operation:", s.ProposedChange.Operation)
	fmt.Fprintf(w, "  %-12s %s\n", "Kind:", s.ProposedChange.GVK.Kind)
	fmt.Fprintf(w, "  %-12s %s/%s\n", "Target:", ns(s.ProposedChange.Namespace), s.ProposedChange.Name)
	fmt.Fprintln(w)

	// Analyzer outputs
	if len(s.AnalyzerOutputs) == 0 {
		fmt.Fprintln(w, "No analyzer produced output for this change.")
	}
	for _, out := range s.AnalyzerOutputs {
		renderAnalyzerOutput(w, &out)
	}

	// Errors
	if len(s.CollectionErrors) > 0 {
		fmt.Fprintln(w, bold("Collection errors"))
		for _, e := range s.CollectionErrors {
			fmt.Fprintf(w, "  [%s] %s\n", e.Component, e.Message)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func renderAnalyzerOutput(w io.Writer, out *types.AnalyzerOutput) {
	fmt.Fprintln(w, bold(fmt.Sprintf("Analyzer: %s  (%dms)", out.AnalyzerName, out.DurationMS)))

	// Data source status
	if len(out.DataSourceStatus) > 0 {
		fmt.Fprintln(w, label("  Data sources:"))
		for name, status := range out.DataSourceStatus {
			fmt.Fprintf(w, "    - %s: %s\n", name, status)
		}
	}

	// Affected resources
	fmt.Fprintf(w, "  %s %d\n", label("Affected resources:"), len(out.AffectedResources))
	for i, r := range out.AffectedResources {
		fmt.Fprintf(w, "    %d. %s  %s/%s/%s\n", i+1, r.ImpactType, r.Kind, ns(r.Namespace), r.Name)
		if r.Reason != "" {
			fmt.Fprintf(w, "       %s\n", r.Reason)
		}
	}

	// Context hints
	if len(out.ContextHints) > 0 {
		fmt.Fprintln(w, label("  Context hints:"))
		for _, h := range out.ContextHints {
			fmt.Fprintf(w, "    - %s\n", h)
		}
	}
	fmt.Fprintln(w)
}

// Presentation helpers — kept inline to avoid an external dep for now.
// When we move to a richer CLI, we'll switch to fatih/color or lipgloss.

func bold(s string) string {
	return s
}

func label(s string) string {
	return s
}

func separator() string {
	return strings.Repeat("─", 60)
}

func ns(s string) string {
	if s == "" {
		return "(cluster-scoped)"
	}
	return s
}

func maybeContext(ctx string) string {
	if ctx == "" {
		return ""
	}
	return "| cluster: " + ctx
}
