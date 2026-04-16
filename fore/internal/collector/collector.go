// Package collector orchestrates the data collection pipeline:
//  1. Takes raw YAML input.
//  2. Parses it into a ProposedChange.
//  3. Routes to matching analyzers via the registry.
//  4. Assembles a final ClusterSnapshot.
//
// The collector itself is simple glue — the real work lives in the analyzers.
package collector

import (
	"context"
	"fmt"
	"time"

	"foresight/internal/analyzer"
	"foresight/internal/parser"
	"foresight/pkg/types"
)

const schemaVersion = "0.1.0"
const generatedBy = "foresight/0.1.0"

// Collector is the top-level orchestrator.
type Collector struct {
	registry *analyzer.Registry
	parser   *parser.Parser
	sources  *types.DataSources
	context  string // cluster context name (kube-context or custom label)
}

// Config controls how a Collector is built.
type Config struct {
	Registry       *analyzer.Registry
	Parser         *parser.Parser
	Sources        *types.DataSources
	ClusterContext string
}

// New creates a Collector. All fields of Config are required except
// ClusterContext.
func New(cfg Config) (*Collector, error) {
	if cfg.Registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if cfg.Parser == nil {
		return nil, fmt.Errorf("parser is required")
	}
	if cfg.Sources == nil {
		return nil, fmt.Errorf("sources is required (even if clients within are nil)")
	}
	return &Collector{
		registry: cfg.Registry,
		parser:   cfg.Parser,
		sources:  cfg.Sources,
		context:  cfg.ClusterContext,
	}, nil
}

// Collect runs the full pipeline and returns a ClusterSnapshot.
//
// The returned snapshot always has valid Metadata and ProposedChange, even
// when individual analyzers fail — their errors are recorded in
// snapshot.CollectionErrors rather than being propagated up.
func (c *Collector) Collect(ctx context.Context, rawYAML []byte) (*types.ClusterSnapshot, error) {
	start := time.Now()

	change, err := c.parser.Parse(ctx, rawYAML)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	snapshot := &types.ClusterSnapshot{
		Metadata: types.SnapshotMetadata{
			SchemaVersion:  schemaVersion,
			GeneratedAt:    start,
			GeneratedBy:    generatedBy,
			ClusterContext: c.context,
		},
		ProposedChange:   *change,
		AnalyzerOutputs:  []types.AnalyzerOutput{},
		CollectionErrors: []types.CollectionError{},
	}

	// Find analyzers that claim this GVK.
	matched := c.registry.Find(change.GVK, change.Parsed)
	if len(matched) == 0 {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, types.CollectionError{
			Component: "collector",
			Message:   fmt.Sprintf("no analyzer registered for %s", change.GVK.String()),
		})
		snapshot.Metadata.CollectionTimeMS = time.Since(start).Milliseconds()
		return snapshot, nil
	}

	// Run each matched analyzer. We run them sequentially for now — the
	// analyzer set is small and sequential is easier to debug. If this
	// becomes a bottleneck we parallelize here, not in the analyzers.
	for _, a := range matched {
		out, err := a.Collect(ctx, change, c.sources)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, types.CollectionError{
				Component: a.Name(),
				Message:   err.Error(),
			})
			continue
		}
		if out != nil {
			snapshot.AnalyzerOutputs = append(snapshot.AnalyzerOutputs, *out)
		}
	}

	snapshot.Metadata.CollectionTimeMS = time.Since(start).Milliseconds()
	return snapshot, nil
}
