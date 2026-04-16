package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"foresight/internal/analyzer"
	"foresight/internal/analyzer/istio"
	"foresight/internal/collector"
	"foresight/internal/parser"
	"foresight/internal/sources"
	"foresight/pkg/types"
)

// analyzeFlags holds CLI flags for the analyze command.
type analyzeFlags struct {
	file            string
	output          string // "json" or "pretty"
	dryParse        bool
	promURL         string
	promMode        string // "auto-detect", "direct", "port-forward"
	clusterContext  string
	timeoutSeconds  int
}

func newAnalyzeCmd() *cobra.Command {
	var f analyzeFlags

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze the impact of a proposed Kubernetes config change",
		Long: `Analyze reads a YAML config change, routes it to the matching analyzer(s),
collects live cluster data, and produces a snapshot describing the change's
impact. The snapshot is the input the AI agent will reason about.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(cmd.Context(), &f)
		},
	}

	cmd.Flags().StringVarP(&f.file, "file", "f", "", "path to the proposed config YAML (required, or '-' for stdin)")
	cmd.Flags().StringVarP(&f.output, "output", "o", "pretty", "output format: json | pretty")
	cmd.Flags().BoolVar(&f.dryParse, "dry-parse", false, "parse the YAML but skip cluster calls (useful for testing)")
	cmd.Flags().StringVar(&f.promURL, "prometheus-url", "", "Prometheus URL (used with --prometheus-mode=direct or port-forward)")
	cmd.Flags().StringVar(&f.promMode, "prometheus-mode", "auto-detect", "how to connect to Prometheus: auto-detect | direct | port-forward")
	cmd.Flags().StringVar(&f.clusterContext, "cluster-context", "", "optional label for the cluster in the output snapshot")
	cmd.Flags().IntVar(&f.timeoutSeconds, "timeout", 60, "overall timeout for the analysis, in seconds")

	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func runAnalyze(parentCtx context.Context, f *analyzeFlags) error {
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(f.timeoutSeconds)*time.Second)
	defer cancel()

	// Read YAML input (file or stdin).
	rawYAML, err := readInput(f.file)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	// Build data sources. In dry-parse mode we skip cluster calls entirely.
	ds := &types.DataSources{}
	var k8s *sources.K8sClient
	if !f.dryParse {
		k8s, err = sources.NewK8sClient()
		if err != nil {
			slog.Warn("kubernetes client unavailable; continuing with static analysis", "error", err)
		} else {
			ds.K8s = k8s
		}

		prom, err := buildPromClient(ctx, f, k8s)
		if err != nil {
			slog.Warn("prometheus client unavailable; live traffic data will be missing", "error", err)
		} else {
			ds.Prometheus = prom
		}

		ds.Metrics = sources.NewMetricsClient()
	}

	// Wire up registry with all built-in analyzers.
	reg := buildRegistry()

	// Build the collector.
	var k8sIface types.K8sClient
	if k8s != nil {
		k8sIface = k8s
	}
	p := parser.New(k8sIface)

	coll, err := collector.New(collector.Config{
		Registry:       reg,
		Parser:         p,
		Sources:        ds,
		ClusterContext: f.clusterContext,
	})
	if err != nil {
		return fmt.Errorf("build collector: %w", err)
	}

	// Run collection.
	snapshot, err := coll.Collect(ctx, rawYAML)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}

	return emitSnapshot(snapshot, f.output)
}

// readInput reads YAML from a file or stdin ("-").
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// buildPromClient constructs a Prometheus client based on the requested mode.
func buildPromClient(ctx context.Context, f *analyzeFlags, k8s *sources.K8sClient) (*sources.PromClient, error) {
	mode := sources.PromConnectionMode(f.promMode)

	cfg := sources.PromConfig{
		Mode:      mode,
		URL:       f.promURL,
		K8sClient: k8s,
	}

	// Sensible default: if user passed --prometheus-url but left mode as auto-detect,
	// treat it as direct.
	if f.promURL != "" && mode == sources.PromModeAutoDetect {
		cfg.Mode = sources.PromModeDirect
	}

	return sources.NewPromClient(ctx, cfg)
}

// buildRegistry creates the analyzer registry with all built-in analyzers.
// Future analyzers (NetworkPolicy, ResourceQuota) register here.
func buildRegistry() *analyzer.Registry {
	reg := analyzer.NewRegistry()
	_ = reg.Register(istio.NewAuthPolicyAnalyzer())
	_ = reg.Register(istio.NewVirtualServiceAnalyzer())
	// _ = reg.Register(networkpolicy.NewAnalyzer())           // TODO
	// _ = reg.Register(resourcequota.NewAnalyzer())           // TODO
	return reg
}

// emitSnapshot renders the snapshot in the requested format.
func emitSnapshot(snapshot *types.ClusterSnapshot, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snapshot)
	case "pretty":
		return renderPretty(os.Stdout, snapshot)
	default:
		return fmt.Errorf("unknown output format %q (want: json | pretty)", format)
	}
}
