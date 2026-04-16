// Package main is the Foresight CLI entry point.
//
// Example:
//
//	foresight analyze -f change.yaml
//	foresight analyze -f change.yaml --prometheus-url http://localhost:9090
//	foresight analyze -f change.yaml --dry-parse
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "0.1.0-dev"

func main() {
	root := &cobra.Command{
		Use:   "foresight",
		Short: "Predict the impact of a Kubernetes config change before you apply it.",
		Long: `Foresight collects live cluster data — traffic, state, resource usage —
and produces a standardized snapshot for downstream impact analysis.

Analyzers are pluggable per resource type: Istio AuthorizationPolicy and
VirtualService, NetworkPolicy (standard + Cilium), and ResourceQuota are
the initial set.`,
		SilenceUsage: true,
	}

	root.Version = Version
	root.AddCommand(newAnalyzeCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newInfoCmd())

	// Configure global logging. Verbose flag promotes to debug level.
	var verbose bool
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
	cobra.OnInitialize(func() {
		level := slog.LevelInfo
		if verbose {
			level = slog.LevelDebug
		}
		handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
		slog.SetDefault(slog.New(handler))
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
