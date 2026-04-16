package analyzer

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"foresight/pkg/types"
)

// Registry is a thread-safe collection of registered Analyzers, indexed by GVK.
// The collector uses it to route each incoming change to the right analyzer(s).
type Registry struct {
	mu        sync.RWMutex
	analyzers []Analyzer
	byGVK     map[types.GVK][]Analyzer
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byGVK: make(map[types.GVK][]Analyzer),
	}
}

// Register adds an analyzer. It is valid to register multiple analyzers for
// the same GVK — they will all get a chance to CanAnalyze() the resource.
func (r *Registry) Register(a Analyzer) error {
	if a == nil {
		return fmt.Errorf("cannot register nil analyzer")
	}
	if a.Name() == "" {
		return fmt.Errorf("analyzer must have a non-empty Name")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Duplicate-name check
	for _, existing := range r.analyzers {
		if existing.Name() == a.Name() {
			return fmt.Errorf("analyzer %q is already registered", a.Name())
		}
	}

	r.analyzers = append(r.analyzers, a)
	for _, gvk := range a.SupportedKinds() {
		r.byGVK[gvk] = append(r.byGVK[gvk], a)
	}
	return nil
}

// Find returns all registered analyzers that claim to handle the given GVK
// AND confirm they can analyze the specific resource via CanAnalyze().
func (r *Registry) Find(gvk types.GVK, resource *unstructured.Unstructured) []Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	candidates := r.byGVK[gvk]
	matched := make([]Analyzer, 0, len(candidates))
	for _, a := range candidates {
		if a.CanAnalyze(resource) {
			matched = append(matched, a)
		}
	}
	return matched
}

// All returns every registered analyzer. Useful for diagnostics and listing.
func (r *Registry) All() []Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Analyzer, len(r.analyzers))
	copy(out, r.analyzers)
	return out
}

// SupportedKinds returns the union of all GVKs known to the registry.
func (r *Registry) SupportedKinds() []types.GVK {
	r.mu.RLock()
	defer r.mu.RUnlock()
	kinds := make([]types.GVK, 0, len(r.byGVK))
	for gvk := range r.byGVK {
		kinds = append(kinds, gvk)
	}
	return kinds
}
