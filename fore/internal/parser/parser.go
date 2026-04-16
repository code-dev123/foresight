// Package parser handles turning raw YAML input into a normalized ProposedChange.
// It also handles type detection — identifying the GVK of the incoming resource.
package parser

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"

	"foresight/pkg/types"
)

// Parser converts raw YAML into a normalized ProposedChange.
// It can optionally fetch the current state of the resource to determine
// whether the operation is a CREATE or UPDATE.
type Parser struct {
	k8s types.K8sClient // optional — nil means we skip the current-state lookup
}

// New creates a Parser. Pass nil for k8s to skip the current-state lookup
// (useful for --dry-parse mode or when a cluster is not accessible).
func New(k8s types.K8sClient) *Parser {
	return &Parser{k8s: k8s}
}

// Parse converts raw YAML bytes into a ProposedChange.
//
// Behavior:
//   - Parses the YAML into an unstructured object.
//   - Extracts GVK, namespace, and name.
//   - If a K8sClient was provided, looks up current state to set Operation
//     to CREATE or UPDATE correctly. Without a client, defaults to CREATE.
func (p *Parser) Parse(ctx context.Context, rawYAML []byte) (*types.ProposedChange, error) {
	if len(rawYAML) == 0 {
		return nil, fmt.Errorf("empty YAML input")
	}

	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(rawYAML, obj); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// Sanity check
	if obj.GetKind() == "" {
		return nil, fmt.Errorf("missing 'kind' in YAML")
	}
	if obj.GetAPIVersion() == "" {
		return nil, fmt.Errorf("missing 'apiVersion' in YAML")
	}

	gvk, err := extractGVK(obj)
	if err != nil {
		return nil, err
	}

	change := &types.ProposedChange{
		Operation: types.OpCreate, // default; may upgrade to OpUpdate below
		GVK:       gvk,
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
		RawYAML:   string(rawYAML),
		Parsed:    obj,
	}

	// If we have cluster access, check if the resource already exists.
	// If it does, this is an UPDATE; capture current state for diff analysis.
	if p.k8s != nil && change.Name != "" {
		current, err := p.k8s.GetResource(ctx, gvk, change.Namespace, change.Name)
		if err == nil && current != nil {
			change.Operation = types.OpUpdate
			change.CurrentState = current
		}
		// Errors here are non-fatal — we just assume CREATE.
	}

	return change, nil
}

// extractGVK pulls Group/Version/Kind out of an unstructured object.
func extractGVK(obj *unstructured.Unstructured) (types.GVK, error) {
	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()

	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return types.GVK{}, fmt.Errorf("parse apiVersion %q: %w", apiVersion, err)
	}

	return types.GVK{
		Group:   gv.Group,
		Version: gv.Version,
		Kind:    kind,
	}, nil
}

// Describe returns a short human-readable summary of a parsed change.
// Useful for CLI output and logs.
func Describe(change *types.ProposedChange) string {
	if change == nil {
		return "<nil change>"
	}
	var parts []string
	parts = append(parts, string(change.Operation))
	parts = append(parts, change.GVK.Kind)
	if change.Namespace != "" {
		parts = append(parts, change.Namespace+"/"+change.Name)
	} else {
		parts = append(parts, change.Name)
	}
	return strings.Join(parts, " ")
}
