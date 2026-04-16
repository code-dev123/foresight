// Package analyzer defines the Analyzer plugin interface and registry.
//
// Adding a new analyzer is a matter of:
//  1. Creating a new sub-package under internal/analyzer/<yourname>/
//  2. Implementing the Analyzer interface below.
//  3. Registering it via registry.Register() in cmd/foresight/main.go.
//
// The collector, parser, and CLI do not need to know about specific analyzers —
// they discover capabilities through the registry at runtime.
package analyzer

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"foresight/pkg/types"
)

// Analyzer is the plugin contract for a resource-type-specific analyzer.
//
// Design notes:
//   - Analyzers are stateless. Any state (clients, config) is injected via
//     constructors in the plugin sub-package.
//   - Analyzers must not panic on missing data sources. If Prometheus is down,
//     return a partial result with DataSourceStatus reflecting that.
//   - Collect must be safe for concurrent use by multiple goroutines.
type Analyzer interface {
	// Name is a stable identifier used in logs and output (e.g., "istio-authpolicy").
	Name() string

	// SupportedKinds lists the GVKs this analyzer can handle.
	// Used by the registry to route incoming changes.
	SupportedKinds() []types.GVK

	// CanAnalyze is the final per-resource check. This handles cases where
	// one analyzer supports multiple variants or needs to inspect the resource
	// before committing. For simple analyzers this can just return true.
	CanAnalyze(resource *unstructured.Unstructured) bool

	// Collect is the core work. Given a proposed change and the available
	// data sources, produce a standardized AnalyzerOutput.
	Collect(ctx context.Context, change *types.ProposedChange, sources *types.DataSources) (*types.AnalyzerOutput, error)
}
