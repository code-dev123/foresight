// Package istio contains analyzers for Istio resources.
//
// This file implements the AuthorizationPolicy analyzer. It answers the
// question: "if this AuthorizationPolicy is applied, which current traffic
// flows will be blocked?"
//
// Approach:
//  1. Parse the proposed AuthorizationPolicy to understand its selector
//     (which workloads it affects) and its rules (who is allowed to call).
//  2. Query Prometheus via istio_requests_total to discover which workloads
//     currently send traffic to the selected targets.
//  3. For each current source, check whether the proposed policy's allow
//     rules would permit it. Sources that wouldn't be permitted are flagged
//     as BLOCKED in the standardized AffectedResources output.
//
// The implementation handles the common authorization patterns; uncommon
// ones (JWT, custom principals, complex path matches) are noted in
// context_hints for the AI agent to reason about further.
package istio

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"foresight/internal/analyzer"
	"foresight/pkg/types"
)

// Ensure we implement the interface at compile time.
var _ analyzer.Analyzer = (*AuthPolicyAnalyzer)(nil)

// AuthPolicyAnalyzer analyzes proposed Istio AuthorizationPolicy changes.
type AuthPolicyAnalyzer struct{}

// NewAuthPolicyAnalyzer constructs a new analyzer. It's stateless; the
// constructor exists for symmetry with future analyzers that will need
// configuration (e.g., Prometheus query overrides).
func NewAuthPolicyAnalyzer() *AuthPolicyAnalyzer {
	return &AuthPolicyAnalyzer{}
}

// Name returns the stable identifier used in logs and output.
func (a *AuthPolicyAnalyzer) Name() string {
	return "istio-authpolicy"
}

// SupportedKinds lists the GVKs this analyzer handles.
// We support both v1 (GA) and v1beta1 (still common in older clusters).
func (a *AuthPolicyAnalyzer) SupportedKinds() []types.GVK {
	return []types.GVK{
		{Group: "security.istio.io", Version: "v1", Kind: "AuthorizationPolicy"},
		{Group: "security.istio.io", Version: "v1beta1", Kind: "AuthorizationPolicy"},
	}
}

// CanAnalyze is a final check per resource. For AuthorizationPolicy we accept
// anything with the matching GVK — policy action and rule shape are handled
// downstream.
func (a *AuthPolicyAnalyzer) CanAnalyze(resource *unstructured.Unstructured) bool {
	if resource == nil {
		return false
	}
	return resource.GetKind() == "AuthorizationPolicy"
}

// Collect performs the impact analysis for an AuthorizationPolicy change.
func (a *AuthPolicyAnalyzer) Collect(
	ctx context.Context,
	change *types.ProposedChange,
	sources *types.DataSources,
) (*types.AnalyzerOutput, error) {
	start := time.Now()

	output := &types.AnalyzerOutput{
		AnalyzerName:     a.Name(),
		CollectedAt:      start,
		AffectedResources: []types.AffectedResource{},
		ContextHints:      []string{},
		LiveData:          map[string]interface{}{},
		DataSourceStatus:  map[string]string{},
	}
	defer func() {
		output.DurationMS = time.Since(start).Milliseconds()
	}()

	policy, err := parseAuthPolicy(change.Parsed)
	if err != nil {
		return nil, fmt.Errorf("parse authpolicy: %w", err)
	}
	output.LiveData["policy_spec"] = policy

	// Flag unusual configurations for the AI agent to reason about.
	addContextHints(output, policy)

	// If there's no Prometheus, we can't determine live traffic. Return what
	// we can from static analysis alone.
	if sources.Prometheus == nil {
		output.DataSourceStatus["prometheus"] = "unavailable — falling back to static analysis"
		output.ContextHints = append(output.ContextHints,
			"Prometheus was unavailable; live traffic impact could not be measured.")
		return output, nil
	}

	// Confirm Prometheus is actually reachable.
	if err := sources.Prometheus.Healthy(ctx); err != nil {
		output.DataSourceStatus["prometheus"] = fmt.Sprintf("unhealthy: %v", err)
		output.ContextHints = append(output.ContextHints,
			"Prometheus health check failed; live traffic data could not be retrieved.")
		return output, nil
	}
	output.DataSourceStatus["prometheus"] = "ok"

	// Determine which workloads this policy selects.
	targetNamespace := change.Namespace
	targetSelector := policy.SelectorLabels
	isNamespaceWide := len(targetSelector) == 0

	if isNamespaceWide {
		output.ContextHints = append(output.ContextHints,
			fmt.Sprintf("Policy has no selector — applies to all workloads in namespace %q.", targetNamespace))
	}

	// Query current inbound traffic for the targeted workloads.
	edges, err := queryInboundTraffic(ctx, sources.Prometheus, targetNamespace, targetSelector)
	if err != nil {
		output.DataSourceStatus["prometheus"] = fmt.Sprintf("query error: %v", err)
		return output, nil
	}
	output.LiveData["inbound_traffic_edges"] = edges

	// For each current traffic source, check whether the policy would permit it.
	for _, edge := range edges {
		allowed := policyPermits(policy, edge)
		if allowed {
			continue
		}

		output.AffectedResources = append(output.AffectedResources, types.AffectedResource{
			Kind:       "Workload",
			Namespace:  edge.SourceNamespace,
			Name:       edge.SourceWorkload,
			ImpactType: types.ImpactBlocked,
			Reason: fmt.Sprintf("Currently sending %.1f RPS to %s/%s; not permitted by proposed policy",
				edge.RPS, edge.DestNamespace, edge.DestWorkload),
			Evidence: map[string]interface{}{
				"source_workload":      edge.SourceWorkload,
				"source_namespace":     edge.SourceNamespace,
				"source_principal":     edge.SourcePrincipal,
				"destination_workload": edge.DestWorkload,
				"destination_service":  edge.DestService,
				"rps":                  edge.RPS,
				"error_rate":           edge.ErrorRate,
			},
		})
	}

	// Summary hints for the agent.
	output.ContextHints = append(output.ContextHints,
		fmt.Sprintf("Policy action: %s. Target namespace: %s. %d inbound traffic edges observed, %d would be blocked.",
			policy.Action, targetNamespace, len(edges), len(output.AffectedResources)))

	return output, nil
}

// -----------------------------------------------------------------------------
// Parsing the AuthorizationPolicy spec
// -----------------------------------------------------------------------------

// authPolicySpec is a simplified view of AuthorizationPolicy.spec, holding
// only the fields we currently reason about. It's deliberately narrow — we
// extend it as we add handling for more policy features.
type authPolicySpec struct {
	Action         string            `json:"action"`          // ALLOW, DENY, AUDIT, CUSTOM
	SelectorLabels map[string]string `json:"selector_labels"` // may be empty (namespace-wide)
	Rules          []authRule        `json:"rules"`
}

// authRule is a simplified view of a rule inside an AuthorizationPolicy.
type authRule struct {
	FromPrincipals  []string `json:"from_principals,omitempty"`
	FromNamespaces  []string `json:"from_namespaces,omitempty"`
	ToOperations    []string `json:"to_operations,omitempty"`    // not yet used for matching
	WhenConditions  []string `json:"when_conditions,omitempty"`  // informational only
}

// parseAuthPolicy extracts the fields we care about from the unstructured object.
func parseAuthPolicy(obj *unstructured.Unstructured) (*authPolicySpec, error) {
	if obj == nil {
		return nil, fmt.Errorf("nil object")
	}

	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	if !found {
		return &authPolicySpec{Action: "ALLOW"}, nil
	}

	p := &authPolicySpec{Action: "ALLOW"} // Istio default

	// Action
	if action, ok := spec["action"].(string); ok {
		p.Action = strings.ToUpper(action)
	}

	// Selector
	if sel, ok := spec["selector"].(map[string]interface{}); ok {
		if ml, ok := sel["matchLabels"].(map[string]interface{}); ok {
			p.SelectorLabels = make(map[string]string, len(ml))
			for k, v := range ml {
				if vs, ok := v.(string); ok {
					p.SelectorLabels[k] = vs
				}
			}
		}
	}

	// Rules
	if rules, ok := spec["rules"].([]interface{}); ok {
		for _, r := range rules {
			rm, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			p.Rules = append(p.Rules, parseAuthRule(rm))
		}
	}

	return p, nil
}

func parseAuthRule(rm map[string]interface{}) authRule {
	var rule authRule

	// from[*].source
	if fromList, ok := rm["from"].([]interface{}); ok {
		for _, f := range fromList {
			fm, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			if src, ok := fm["source"].(map[string]interface{}); ok {
				rule.FromPrincipals = append(rule.FromPrincipals, stringSlice(src["principals"])...)
				rule.FromNamespaces = append(rule.FromNamespaces, stringSlice(src["namespaces"])...)
			}
		}
	}

	// to[*].operation (kept as raw strings; we don't currently match ops)
	if toList, ok := rm["to"].([]interface{}); ok {
		for _, t := range toList {
			tm, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			if op, ok := tm["operation"].(map[string]interface{}); ok {
				if methods := stringSlice(op["methods"]); len(methods) > 0 {
					rule.ToOperations = append(rule.ToOperations, "methods:"+strings.Join(methods, ","))
				}
				if paths := stringSlice(op["paths"]); len(paths) > 0 {
					rule.ToOperations = append(rule.ToOperations, "paths:"+strings.Join(paths, ","))
				}
			}
		}
	}

	// when[*]
	if whenList, ok := rm["when"].([]interface{}); ok {
		for _, w := range whenList {
			wm, ok := w.(map[string]interface{})
			if !ok {
				continue
			}
			if key, ok := wm["key"].(string); ok {
				rule.WhenConditions = append(rule.WhenConditions, key)
			}
		}
	}

	return rule
}

func stringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// addContextHints flags policy features that complicate static impact analysis.
// The AI agent can factor these into its final confidence rating.
func addContextHints(out *types.AnalyzerOutput, p *authPolicySpec) {
	for _, rule := range p.Rules {
		if len(rule.WhenConditions) > 0 {
			out.ContextHints = append(out.ContextHints,
				fmt.Sprintf("Policy uses 'when' conditions (%s); runtime impact depends on request attributes.",
					strings.Join(rule.WhenConditions, ", ")))
		}
		if len(rule.ToOperations) > 0 {
			out.ContextHints = append(out.ContextHints,
				"Policy has 'to.operation' constraints (methods/paths); only specific request types are affected.")
		}
	}
	if p.Action != "ALLOW" && p.Action != "" {
		out.ContextHints = append(out.ContextHints,
			fmt.Sprintf("Policy action is %s — impact semantics differ from the common ALLOW case.", p.Action))
	}
}

// -----------------------------------------------------------------------------
// Prometheus: querying live inbound traffic
// -----------------------------------------------------------------------------

// trafficEdge represents one observed source→destination flow.
type trafficEdge struct {
	SourceWorkload   string  `json:"source_workload"`
	SourceNamespace  string  `json:"source_namespace"`
	SourcePrincipal  string  `json:"source_principal"`
	DestWorkload     string  `json:"dest_workload"`
	DestNamespace    string  `json:"dest_namespace"`
	DestService      string  `json:"dest_service"`
	RPS              float64 `json:"rps"`
	ErrorRate        float64 `json:"error_rate"`
}

// queryInboundTraffic returns all source→destination edges where the
// destination matches the policy's target namespace and selector.
//
// The queries use Istio's standard Prometheus metrics. The time window is
// 5 minutes — short enough to be responsive, long enough to smooth out
// per-second noise.
func queryInboundTraffic(
	ctx context.Context,
	prom types.PrometheusClient,
	targetNamespace string,
	selector map[string]string,
) ([]trafficEdge, error) {
	// Build the workload filter. When selector is empty we target the
	// whole namespace; otherwise we filter by the "app" label if present
	// (convention for Istio), falling back to namespace-only otherwise.
	workloadFilter := fmt.Sprintf(`destination_workload_namespace="%s"`, targetNamespace)
	if app, ok := selector["app"]; ok {
		workloadFilter += fmt.Sprintf(`, destination_app="%s"`, app)
	}

	rpsQuery := fmt.Sprintf(`
sum by (source_workload, source_workload_namespace, source_principal, destination_workload, destination_service_name) (
  rate(istio_requests_total{reporter="destination", %s}[5m])
)`, workloadFilter)

	rpsResult, err := prom.Query(ctx, rpsQuery)
	if err != nil {
		return nil, fmt.Errorf("inbound rps query: %w", err)
	}

	errorQuery := fmt.Sprintf(`
sum by (source_workload, source_workload_namespace, destination_workload) (
  rate(istio_requests_total{reporter="destination", response_code=~"5..", %s}[5m])
)`, workloadFilter)

	errorResult, err := prom.Query(ctx, errorQuery)
	if err != nil {
		// Non-fatal: we still have RPS data.
		errorResult = types.QueryResult{}
	}

	// Index errors by (source, dest) so we can join cheaply.
	errorIdx := map[string]float64{}
	for _, s := range errorResult.Series {
		key := s.Labels["source_workload"] + "|" + s.Labels["source_workload_namespace"] + "|" + s.Labels["destination_workload"]
		if len(s.Samples) > 0 {
			errorIdx[key] = s.Samples[0].Value
		}
	}

	edges := make([]trafficEdge, 0, len(rpsResult.Series))
	for _, s := range rpsResult.Series {
		if len(s.Samples) == 0 {
			continue
		}
		rps := s.Samples[0].Value
		if rps <= 0 {
			continue
		}

		srcWl := s.Labels["source_workload"]
		srcNs := s.Labels["source_workload_namespace"]
		dstWl := s.Labels["destination_workload"]
		dstSvc := s.Labels["destination_service_name"]

		key := srcWl + "|" + srcNs + "|" + dstWl
		errorRPS := errorIdx[key]
		errorRate := 0.0
		if rps > 0 {
			errorRate = errorRPS / rps
		}

		edges = append(edges, trafficEdge{
			SourceWorkload:  srcWl,
			SourceNamespace: srcNs,
			SourcePrincipal: s.Labels["source_principal"],
			DestWorkload:    dstWl,
			DestNamespace:   targetNamespace,
			DestService:     dstSvc,
			RPS:             rps,
			ErrorRate:       errorRate,
		})
	}

	return edges, nil
}

// -----------------------------------------------------------------------------
// Policy evaluation: would this edge be permitted?
// -----------------------------------------------------------------------------

// policyPermits reports whether the proposed policy would allow the given edge.
//
// Semantics (simplified):
//   - If no ALLOW rules match the source, traffic is blocked.
//   - If the policy has no rules at all with action ALLOW, it denies everything.
//   - DENY/CUSTOM/AUDIT actions: we flag them in hints and conservatively
//     treat them as "needs AI reasoning" by returning true here, so we don't
//     produce false positives. The AI agent sees the hints and reasons.
//
// This covers the 90% case; edge cases are flagged to the agent.
func policyPermits(p *authPolicySpec, edge trafficEdge) bool {
	// For non-ALLOW actions, defer to the AI agent.
	if p.Action != "ALLOW" && p.Action != "" {
		return true
	}

	// ALLOW with no rules denies everything.
	if len(p.Rules) == 0 {
		return false
	}

	// ALLOW with rules: traffic is permitted if ANY rule matches.
	for _, rule := range p.Rules {
		if ruleMatches(rule, edge) {
			return true
		}
	}
	return false
}

// ruleMatches returns true if the edge satisfies the rule's from constraints.
// We currently ignore `to.operation` and `when` constraints — matching on
// those would require request-level data we don't have here. Instead, those
// are surfaced as context_hints so the AI agent knows the static answer is
// an upper bound on what's allowed.
func ruleMatches(rule authRule, edge trafficEdge) bool {
	// If the rule has no source constraints, it matches anything.
	if len(rule.FromPrincipals) == 0 && len(rule.FromNamespaces) == 0 {
		return true
	}

	if principalMatches(rule.FromPrincipals, edge.SourcePrincipal) {
		return true
	}
	if namespaceMatches(rule.FromNamespaces, edge.SourceNamespace) {
		return true
	}
	return false
}

// principalMatches handles Istio's principal format (cluster.local/ns/X/sa/Y).
// Supports exact match and simple wildcard suffixes.
func principalMatches(allowed []string, observed string) bool {
	if observed == "" {
		return false
	}
	for _, p := range allowed {
		if p == "*" {
			return true
		}
		if p == observed {
			return true
		}
		// Wildcard suffix: "cluster.local/ns/foo/*"
		if strings.HasSuffix(p, "/*") {
			prefix := strings.TrimSuffix(p, "/*")
			if strings.HasPrefix(observed, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func namespaceMatches(allowed []string, observed string) bool {
	if observed == "" {
		return false
	}
	for _, ns := range allowed {
		if ns == "*" || ns == observed {
			return true
		}
	}
	return false
}
