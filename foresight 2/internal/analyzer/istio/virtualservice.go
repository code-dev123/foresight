// Package istio — VirtualService analyzer.
//
// VirtualService changes are among the most common sources of mesh incidents:
// a subset weight shifted too aggressively, a route match clause tightened
// incorrectly, or a destination host typo. This analyzer focuses on the
// patterns that actually break production:
//
//  1. Traffic weight shifts — "90/10" becomes "100/0", sending all traffic to
//     a subset that may have a higher error rate.
//  2. Route additions/removals — a match clause that previously caught /api/v1
//     is removed, so that path now falls through to default routing.
//  3. Destination changes — the target host, subset, or port changes entirely.
//  4. Policy additions — new fault injections, timeouts, or retries. These
//     don't block traffic but can silently degrade it; we surface them as
//     context hints for the AI agent.
//
// The analyzer compares CurrentState to Parsed to detect what changed, then
// queries Prometheus to quantify the risk of each change.
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

// Compile-time interface check.
var _ analyzer.Analyzer = (*VirtualServiceAnalyzer)(nil)

// VirtualServiceAnalyzer analyzes proposed Istio VirtualService changes.
type VirtualServiceAnalyzer struct{}

// NewVirtualServiceAnalyzer constructs a stateless VirtualService analyzer.
func NewVirtualServiceAnalyzer() *VirtualServiceAnalyzer {
	return &VirtualServiceAnalyzer{}
}

// Name returns the stable identifier used in logs and output.
func (a *VirtualServiceAnalyzer) Name() string {
	return "istio-virtualservice"
}

// SupportedKinds lists the GVKs this analyzer handles.
// Istio uses networking.istio.io for VirtualService; both v1 (GA) and v1beta1
// are common in production clusters.
func (a *VirtualServiceAnalyzer) SupportedKinds() []types.GVK {
	return []types.GVK{
		{Group: "networking.istio.io", Version: "v1", Kind: "VirtualService"},
		{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualService"},
	}
}

// CanAnalyze is a final per-resource gate.
func (a *VirtualServiceAnalyzer) CanAnalyze(resource *unstructured.Unstructured) bool {
	if resource == nil {
		return false
	}
	return resource.GetKind() == "VirtualService"
}

// Collect performs impact analysis for a VirtualService change.
func (a *VirtualServiceAnalyzer) Collect(
	ctx context.Context,
	change *types.ProposedChange,
	sources *types.DataSources,
) (*types.AnalyzerOutput, error) {
	start := time.Now()

	output := &types.AnalyzerOutput{
		AnalyzerName:      a.Name(),
		CollectedAt:       start,
		AffectedResources: []types.AffectedResource{},
		ContextHints:      []string{},
		LiveData:          map[string]interface{}{},
		DataSourceStatus:  map[string]string{},
	}
	defer func() {
		output.DurationMS = time.Since(start).Milliseconds()
	}()

	proposed, err := parseVirtualService(change.Parsed)
	if err != nil {
		return nil, fmt.Errorf("parse virtualservice: %w", err)
	}
	output.LiveData["proposed_spec"] = proposed

	// For UPDATE operations we can compute a structured diff. For CREATE
	// everything is "new," so we treat every route as a potentially-new
	// routing decision.
	var current *virtualServiceSpec
	if change.Operation == types.OpUpdate && change.CurrentState != nil {
		current, err = parseVirtualService(change.CurrentState)
		if err != nil {
			output.ContextHints = append(output.ContextHints,
				fmt.Sprintf("could not parse current state for diff: %v", err))
		} else {
			output.LiveData["current_spec"] = current
		}
	}

	// Diff the two specs — this is where we detect weight shifts, route
	// additions/removals, destination changes, etc.
	diff := diffVirtualServices(current, proposed)
	output.LiveData["diff"] = diff

	// Static context hints that don't need Prometheus.
	addVSContextHints(output, proposed, diff)

	// Without Prometheus we report the diff but can't quantify impact.
	if sources.Prometheus == nil {
		output.DataSourceStatus["prometheus"] = "unavailable — static diff only"
		output.ContextHints = append(output.ContextHints,
			"Prometheus unavailable; traffic impact is described structurally but not quantified.")
		// Still populate affected resources from the diff — downstream needs them.
		for _, d := range diff.DestinationChanges {
			output.AffectedResources = append(output.AffectedResources, destinationChangeToResource(d, 0))
		}
		return output, nil
	}
	if err := sources.Prometheus.Healthy(ctx); err != nil {
		output.DataSourceStatus["prometheus"] = fmt.Sprintf("unhealthy: %v", err)
		return output, nil
	}
	output.DataSourceStatus["prometheus"] = "ok"

	// Query current traffic flowing to each host mentioned in the spec.
	// We need this to know "how much" traffic is being re-routed.
	hosts := collectAllHosts(proposed, current)
	hostTraffic := map[string]float64{}
	for _, host := range hosts {
		rps, err := queryHostTraffic(ctx, sources.Prometheus, host, change.Namespace)
		if err == nil {
			hostTraffic[host] = rps
		}
	}
	output.LiveData["host_traffic_rps"] = hostTraffic

	// Query per-subset error rates — this makes weight shifts actionable.
	// "Shifting 100% to v2" is only scary if v2 is actually error-prone.
	subsetHealth := map[string]subsetMetric{}
	for _, h := range hosts {
		metrics, err := querySubsetHealth(ctx, sources.Prometheus, h, change.Namespace)
		if err == nil {
			for k, v := range metrics {
				subsetHealth[k] = v
			}
		}
	}
	output.LiveData["subset_health"] = subsetHealth

	// Build AffectedResources from the diff, enriched with live metrics.
	for _, d := range diff.DestinationChanges {
		output.AffectedResources = append(output.AffectedResources,
			destinationChangeToResource(d, hostTraffic[d.Host]))
	}
	for _, w := range diff.WeightShifts {
		output.AffectedResources = append(output.AffectedResources,
			weightShiftToResource(w, hostTraffic[w.Host], subsetHealth))
	}
	for _, r := range diff.RemovedRoutes {
		output.AffectedResources = append(output.AffectedResources,
			routeRemovalToResource(r))
	}

	return output, nil
}

// -----------------------------------------------------------------------------
// Parsing: VirtualService spec → simplified internal form
// -----------------------------------------------------------------------------

// virtualServiceSpec is a narrowed view of VirtualService.spec holding only
// the fields we currently reason about. Expand as needed.
type virtualServiceSpec struct {
	Hosts    []string   `json:"hosts"`
	Gateways []string   `json:"gateways,omitempty"`
	HTTP     []httpRoute `json:"http,omitempty"`
	TCP      []tcpRoute  `json:"tcp,omitempty"`
	// TLS routes exist too; we note their presence but don't diff them yet.
	HasTLS bool `json:"has_tls,omitempty"`
}

// httpRoute represents a single entry in spec.http.
type httpRoute struct {
	Name        string            `json:"name,omitempty"`
	Match       []routeMatch      `json:"match,omitempty"`
	Routes      []weightedRoute   `json:"routes"`
	Timeout     string            `json:"timeout,omitempty"`
	Retries     *retryPolicy      `json:"retries,omitempty"`
	Fault       map[string]string `json:"fault,omitempty"` // summarized, not full struct
	Redirect    string            `json:"redirect,omitempty"`
	Rewrite     string            `json:"rewrite,omitempty"`
	MirrorHost  string            `json:"mirror_host,omitempty"`
}

// tcpRoute represents a single entry in spec.tcp — we only track destinations.
type tcpRoute struct {
	Routes []weightedRoute `json:"routes"`
}

// routeMatch captures the identifying parts of a match block so we can
// compare them across versions of the spec (for diffing).
type routeMatch struct {
	URI      string            `json:"uri,omitempty"`    // "prefix:/api", "exact:/foo", etc.
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Port     int32             `json:"port,omitempty"`
}

// weightedRoute is a single destination inside a route block.
type weightedRoute struct {
	Host   string `json:"host"`
	Subset string `json:"subset,omitempty"`
	Port   int32  `json:"port,omitempty"`
	Weight int32  `json:"weight"` // defaults to 100 for single-destination routes
}

type retryPolicy struct {
	Attempts      int32  `json:"attempts,omitempty"`
	PerTryTimeout string `json:"per_try_timeout,omitempty"`
	RetryOn       string `json:"retry_on,omitempty"`
}

// parseVirtualService extracts the fields we care about.
func parseVirtualService(obj *unstructured.Unstructured) (*virtualServiceSpec, error) {
	if obj == nil {
		return nil, fmt.Errorf("nil object")
	}

	specMap, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	if !found {
		return &virtualServiceSpec{}, nil
	}

	vs := &virtualServiceSpec{}
	vs.Hosts = stringSlice(specMap["hosts"])
	vs.Gateways = stringSlice(specMap["gateways"])

	if httpList, ok := specMap["http"].([]interface{}); ok {
		for _, h := range httpList {
			if hm, ok := h.(map[string]interface{}); ok {
				vs.HTTP = append(vs.HTTP, parseHTTPRoute(hm))
			}
		}
	}
	if tcpList, ok := specMap["tcp"].([]interface{}); ok {
		for _, t := range tcpList {
			if tm, ok := t.(map[string]interface{}); ok {
				vs.TCP = append(vs.TCP, parseTCPRoute(tm))
			}
		}
	}
	if _, ok := specMap["tls"].([]interface{}); ok {
		vs.HasTLS = true
	}

	return vs, nil
}

func parseHTTPRoute(m map[string]interface{}) httpRoute {
	var h httpRoute
	if name, ok := m["name"].(string); ok {
		h.Name = name
	}
	if matchList, ok := m["match"].([]interface{}); ok {
		for _, mi := range matchList {
			if mm, ok := mi.(map[string]interface{}); ok {
				h.Match = append(h.Match, parseRouteMatch(mm))
			}
		}
	}
	if routeList, ok := m["route"].([]interface{}); ok {
		for _, r := range routeList {
			if rm, ok := r.(map[string]interface{}); ok {
				h.Routes = append(h.Routes, parseWeightedRoute(rm))
			}
		}
	}
	// If a single-destination shortcut was used, normalize weight to 100.
	if len(h.Routes) == 1 && h.Routes[0].Weight == 0 {
		h.Routes[0].Weight = 100
	}
	if timeout, ok := m["timeout"].(string); ok {
		h.Timeout = timeout
	}
	if retries, ok := m["retries"].(map[string]interface{}); ok {
		h.Retries = parseRetryPolicy(retries)
	}
	if fault, ok := m["fault"].(map[string]interface{}); ok {
		h.Fault = summarizeFault(fault)
	}
	if redirect, ok := m["redirect"].(map[string]interface{}); ok {
		if uri, ok := redirect["uri"].(string); ok {
			h.Redirect = uri
		}
	}
	if rewrite, ok := m["rewrite"].(map[string]interface{}); ok {
		if uri, ok := rewrite["uri"].(string); ok {
			h.Rewrite = uri
		}
	}
	if mirror, ok := m["mirror"].(map[string]interface{}); ok {
		if host, ok := mirror["host"].(string); ok {
			h.MirrorHost = host
		}
	}
	return h
}

func parseTCPRoute(m map[string]interface{}) tcpRoute {
	var t tcpRoute
	if routeList, ok := m["route"].([]interface{}); ok {
		for _, r := range routeList {
			if rm, ok := r.(map[string]interface{}); ok {
				t.Routes = append(t.Routes, parseWeightedRoute(rm))
			}
		}
	}
	if len(t.Routes) == 1 && t.Routes[0].Weight == 0 {
		t.Routes[0].Weight = 100
	}
	return t
}

func parseRouteMatch(m map[string]interface{}) routeMatch {
	var rm routeMatch
	if uri, ok := m["uri"].(map[string]interface{}); ok {
		// URI match is one of: exact | prefix | regex. Flatten to "type:value".
		for _, k := range []string{"exact", "prefix", "regex"} {
			if v, ok := uri[k].(string); ok {
				rm.URI = k + ":" + v
				break
			}
		}
	}
	if method, ok := m["method"].(map[string]interface{}); ok {
		if exact, ok := method["exact"].(string); ok {
			rm.Method = exact
		}
	}
	if port, ok := m["port"]; ok {
		rm.Port = toInt32(port)
	}
	if headers, ok := m["headers"].(map[string]interface{}); ok {
		rm.Headers = map[string]string{}
		for k, v := range headers {
			if vm, ok := v.(map[string]interface{}); ok {
				for _, mk := range []string{"exact", "prefix", "regex"} {
					if val, ok := vm[mk].(string); ok {
						rm.Headers[k] = mk + ":" + val
						break
					}
				}
			}
		}
	}
	return rm
}

func parseWeightedRoute(m map[string]interface{}) weightedRoute {
	var r weightedRoute
	if dest, ok := m["destination"].(map[string]interface{}); ok {
		if host, ok := dest["host"].(string); ok {
			r.Host = host
		}
		if subset, ok := dest["subset"].(string); ok {
			r.Subset = subset
		}
		if portMap, ok := dest["port"].(map[string]interface{}); ok {
			if num, ok := portMap["number"]; ok {
				r.Port = toInt32(num)
			}
		}
	}
	if weight, ok := m["weight"]; ok {
		r.Weight = toInt32(weight)
	}
	return r
}

func parseRetryPolicy(m map[string]interface{}) *retryPolicy {
	var r retryPolicy
	if attempts, ok := m["attempts"]; ok {
		r.Attempts = toInt32(attempts)
	}
	if per, ok := m["perTryTimeout"].(string); ok {
		r.PerTryTimeout = per
	}
	if retryOn, ok := m["retryOn"].(string); ok {
		r.RetryOn = retryOn
	}
	return &r
}

// summarizeFault flattens the fault injection config into a short map so it
// can be diffed and logged without carrying the full nested structure.
func summarizeFault(m map[string]interface{}) map[string]string {
	out := map[string]string{}
	if delay, ok := m["delay"].(map[string]interface{}); ok {
		if pct, ok := delay["percentage"].(map[string]interface{}); ok {
			if v, ok := pct["value"]; ok {
				out["delay_percent"] = fmt.Sprintf("%v", v)
			}
		}
		if fixed, ok := delay["fixedDelay"].(string); ok {
			out["delay_duration"] = fixed
		}
	}
	if abort, ok := m["abort"].(map[string]interface{}); ok {
		if pct, ok := abort["percentage"].(map[string]interface{}); ok {
			if v, ok := pct["value"]; ok {
				out["abort_percent"] = fmt.Sprintf("%v", v)
			}
		}
		if code, ok := abort["httpStatus"]; ok {
			out["abort_status"] = fmt.Sprintf("%v", code)
		}
	}
	return out
}

// toInt32 normalizes the various numeric types the unstructured decoder may
// produce (int, int64, float64) into int32.
func toInt32(v interface{}) int32 {
	switch x := v.(type) {
	case int:
		return int32(x)
	case int32:
		return x
	case int64:
		return int32(x)
	case float64:
		return int32(x)
	}
	return 0
}

// -----------------------------------------------------------------------------
// Diffing: detect what changed between current and proposed
// -----------------------------------------------------------------------------

// virtualServiceDiff is the structured delta between two VirtualService specs.
type virtualServiceDiff struct {
	WeightShifts       []weightShift       `json:"weight_shifts,omitempty"`
	DestinationChanges []destinationChange `json:"destination_changes,omitempty"`
	RemovedRoutes      []removedRoute      `json:"removed_routes,omitempty"`
	AddedRoutes        []addedRoute        `json:"added_routes,omitempty"`
	PolicyAdditions    []string            `json:"policy_additions,omitempty"` // fault, timeout, retries, etc.
	HostChanges        []string            `json:"host_changes,omitempty"`
}

// weightShift records a subset whose weight changed between versions.
type weightShift struct {
	RouteName   string `json:"route_name,omitempty"`
	Host        string `json:"host"`
	Subset      string `json:"subset,omitempty"`
	OldWeight   int32  `json:"old_weight"`
	NewWeight   int32  `json:"new_weight"`
}

// destinationChange records a route whose destination host changed entirely.
type destinationChange struct {
	RouteName string `json:"route_name,omitempty"`
	Host      string `json:"host"` // the NEW host
	OldHost   string `json:"old_host,omitempty"`
	MatchDesc string `json:"match_description,omitempty"`
}

// removedRoute describes a match clause that existed before but doesn't anymore.
type removedRoute struct {
	RouteName string       `json:"route_name,omitempty"`
	Match     []routeMatch `json:"match,omitempty"`
	Summary   string       `json:"summary"`
}

type addedRoute struct {
	RouteName string       `json:"route_name,omitempty"`
	Match     []routeMatch `json:"match,omitempty"`
	Summary   string       `json:"summary"`
}

// diffVirtualServices produces a structured diff. When current is nil
// (CREATE), we treat everything as added.
func diffVirtualServices(current, proposed *virtualServiceSpec) virtualServiceDiff {
	var diff virtualServiceDiff

	if proposed == nil {
		return diff
	}

	// CREATE: no current state to compare against. Return added routes only.
	if current == nil {
		for i, r := range proposed.HTTP {
			diff.AddedRoutes = append(diff.AddedRoutes, addedRoute{
				RouteName: r.Name,
				Match:     r.Match,
				Summary:   fmt.Sprintf("http route %d: %s", i, describeRoute(r)),
			})
		}
		return diff
	}

	// Host changes
	if !stringSlicesEqual(current.Hosts, proposed.Hosts) {
		diff.HostChanges = append(diff.HostChanges,
			fmt.Sprintf("hosts changed: %v → %v", current.Hosts, proposed.Hosts))
	}

	// Match HTTP routes by name (preferred) or positional index.
	currentByKey := map[string]httpRoute{}
	for i, r := range current.HTTP {
		key := r.Name
		if key == "" {
			key = fmt.Sprintf("#%d", i)
		}
		currentByKey[key] = r
	}
	proposedByKey := map[string]httpRoute{}
	for i, r := range proposed.HTTP {
		key := r.Name
		if key == "" {
			key = fmt.Sprintf("#%d", i)
		}
		proposedByKey[key] = r
	}

	// Routes that existed but are gone.
	for key, r := range currentByKey {
		if _, exists := proposedByKey[key]; !exists {
			diff.RemovedRoutes = append(diff.RemovedRoutes, removedRoute{
				RouteName: r.Name,
				Match:     r.Match,
				Summary:   fmt.Sprintf("removed: %s", describeRoute(r)),
			})
		}
	}

	// Routes that are new.
	for key, r := range proposedByKey {
		if _, exists := currentByKey[key]; !exists {
			diff.AddedRoutes = append(diff.AddedRoutes, addedRoute{
				RouteName: r.Name,
				Match:     r.Match,
				Summary:   fmt.Sprintf("added: %s", describeRoute(r)),
			})
		}
	}

	// Routes present in both — diff their route destinations and policies.
	for key, pr := range proposedByKey {
		cr, exists := currentByKey[key]
		if !exists {
			continue
		}
		diffRouteDestinations(&diff, key, cr, pr)
		diffRoutePolicies(&diff, key, cr, pr)
	}

	return diff
}

// diffRouteDestinations detects weight shifts and destination host changes
// within a single matched route.
func diffRouteDestinations(diff *virtualServiceDiff, routeKey string, cr, pr httpRoute) {
	// Index destinations by host+subset for comparison.
	crByKey := map[string]weightedRoute{}
	for _, d := range cr.Routes {
		crByKey[d.Host+"/"+d.Subset] = d
	}
	prByKey := map[string]weightedRoute{}
	for _, d := range pr.Routes {
		prByKey[d.Host+"/"+d.Subset] = d
	}

	// Weight shifts: same destination in both, different weights.
	for key, pd := range prByKey {
		if cd, ok := crByKey[key]; ok {
			if cd.Weight != pd.Weight {
				diff.WeightShifts = append(diff.WeightShifts, weightShift{
					RouteName: routeKey,
					Host:      pd.Host,
					Subset:    pd.Subset,
					OldWeight: cd.Weight,
					NewWeight: pd.Weight,
				})
			}
		}
	}

	// Destinations that disappeared — treat as weight dropped to 0.
	for key, cd := range crByKey {
		if _, ok := prByKey[key]; !ok {
			diff.WeightShifts = append(diff.WeightShifts, weightShift{
				RouteName: routeKey,
				Host:      cd.Host,
				Subset:    cd.Subset,
				OldWeight: cd.Weight,
				NewWeight: 0,
			})
		}
	}

	// Destinations that appeared — surface as added, with the implied weight.
	for key, pd := range prByKey {
		if _, ok := crByKey[key]; !ok {
			diff.WeightShifts = append(diff.WeightShifts, weightShift{
				RouteName: routeKey,
				Host:      pd.Host,
				Subset:    pd.Subset,
				OldWeight: 0,
				NewWeight: pd.Weight,
			})
		}
	}

	// Host-level swap detection: if all destinations in a route changed to a
	// different host, that's a destination change rather than a weight shift.
	// We surface it as an additional note.
	if len(cr.Routes) > 0 && len(pr.Routes) > 0 {
		oldHosts := uniqueHosts(cr.Routes)
		newHosts := uniqueHosts(pr.Routes)
		if !stringSetsEqual(oldHosts, newHosts) {
			// Pick a representative old/new host for the output.
			diff.DestinationChanges = append(diff.DestinationChanges, destinationChange{
				RouteName: routeKey,
				Host:      strings.Join(newHosts, ","),
				OldHost:   strings.Join(oldHosts, ","),
				MatchDesc: matchDescription(pr.Match),
			})
		}
	}
}

// diffRoutePolicies detects changes to fault injection, timeout, retries,
// redirect, rewrite, and mirror. These don't block traffic but can silently
// degrade it; we surface them as policy additions for the AI agent to reason about.
func diffRoutePolicies(diff *virtualServiceDiff, routeKey string, cr, pr httpRoute) {
	if cr.Timeout != pr.Timeout {
		diff.PolicyAdditions = append(diff.PolicyAdditions,
			fmt.Sprintf("%s: timeout %q → %q", routeKey, cr.Timeout, pr.Timeout))
	}
	if !retriesEqual(cr.Retries, pr.Retries) {
		diff.PolicyAdditions = append(diff.PolicyAdditions,
			fmt.Sprintf("%s: retries %s → %s", routeKey, describeRetries(cr.Retries), describeRetries(pr.Retries)))
	}
	if !stringMapsEqual(cr.Fault, pr.Fault) {
		diff.PolicyAdditions = append(diff.PolicyAdditions,
			fmt.Sprintf("%s: fault injection changed (%v → %v)", routeKey, cr.Fault, pr.Fault))
	}
	if cr.MirrorHost != pr.MirrorHost {
		diff.PolicyAdditions = append(diff.PolicyAdditions,
			fmt.Sprintf("%s: mirror host %q → %q", routeKey, cr.MirrorHost, pr.MirrorHost))
	}
	if cr.Redirect != pr.Redirect {
		diff.PolicyAdditions = append(diff.PolicyAdditions,
			fmt.Sprintf("%s: redirect %q → %q", routeKey, cr.Redirect, pr.Redirect))
	}
	if cr.Rewrite != pr.Rewrite {
		diff.PolicyAdditions = append(diff.PolicyAdditions,
			fmt.Sprintf("%s: rewrite %q → %q", routeKey, cr.Rewrite, pr.Rewrite))
	}
}

// -----------------------------------------------------------------------------
// Prometheus queries: live traffic and subset health
// -----------------------------------------------------------------------------

// queryHostTraffic returns total inbound RPS across all subsets of a host.
// We use destination_service matching which tolerates FQDN and short-form hosts.
func queryHostTraffic(ctx context.Context, prom types.PrometheusClient, host, namespace string) (float64, error) {
	// Normalize short-form hosts like "checkout" to the namespace-scoped form.
	qHost := host
	if !strings.Contains(host, ".") && namespace != "" {
		qHost = fmt.Sprintf("%s.%s.svc.cluster.local", host, namespace)
	}

	query := fmt.Sprintf(`
sum(rate(istio_requests_total{reporter="destination", destination_service=~"%s|%s.svc.cluster.local|%s"}[5m]))`,
		qHost, host, host)

	result, err := prom.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	if len(result.Series) == 0 || len(result.Series[0].Samples) == 0 {
		return 0, nil
	}
	return result.Series[0].Samples[0].Value, nil
}

// subsetMetric captures per-subset RPS and error rate for the subset-health query.
type subsetMetric struct {
	Host      string  `json:"host"`
	Subset    string  `json:"subset"`
	RPS       float64 `json:"rps"`
	ErrorRate float64 `json:"error_rate"`
}

// querySubsetHealth returns RPS and error rate per destination version/subset.
// Keyed by "host/subset" so callers can look up specific combinations quickly.
func querySubsetHealth(ctx context.Context, prom types.PrometheusClient, host, namespace string) (map[string]subsetMetric, error) {
	qHost := host
	if !strings.Contains(host, ".") && namespace != "" {
		qHost = fmt.Sprintf("%s.%s.svc.cluster.local", host, namespace)
	}

	// Istio tags the destination version via destination_version label
	// (populated from the pod's version label; DestinationRule subsets usually
	// match on the same label).
	rpsQuery := fmt.Sprintf(`
sum by (destination_version) (
  rate(istio_requests_total{reporter="destination", destination_service=~"%s|%s.svc.cluster.local|%s"}[5m])
)`, qHost, host, host)

	errQuery := fmt.Sprintf(`
sum by (destination_version) (
  rate(istio_requests_total{reporter="destination", destination_service=~"%s|%s.svc.cluster.local|%s", response_code=~"5.."}[5m])
)`, qHost, host, host)

	rps, err := prom.Query(ctx, rpsQuery)
	if err != nil {
		return nil, err
	}
	errs, _ := prom.Query(ctx, errQuery)

	errByVersion := map[string]float64{}
	for _, s := range errs.Series {
		v := s.Labels["destination_version"]
		if len(s.Samples) > 0 {
			errByVersion[v] = s.Samples[0].Value
		}
	}

	out := map[string]subsetMetric{}
	for _, s := range rps.Series {
		version := s.Labels["destination_version"]
		if len(s.Samples) == 0 {
			continue
		}
		rpsVal := s.Samples[0].Value
		if rpsVal <= 0 {
			continue
		}
		errRate := 0.0
		if rpsVal > 0 {
			errRate = errByVersion[version] / rpsVal
		}
		key := host + "/" + version
		out[key] = subsetMetric{
			Host:      host,
			Subset:    version,
			RPS:       rpsVal,
			ErrorRate: errRate,
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Translating diff entries to standardized AffectedResource outputs
// -----------------------------------------------------------------------------

// weightShiftToResource wraps a weight shift with live metrics.
// A shift to 0 is treated as BLOCKED; a dominant shift to a subset with high
// error rates is DEGRADED; otherwise REROUTED.
func weightShiftToResource(w weightShift, totalRPS float64, subsetHealth map[string]subsetMetric) types.AffectedResource {
	key := w.Host + "/" + w.Subset
	health := subsetHealth[key]

	var impact types.ImpactType
	var reason string

	switch {
	case w.NewWeight == 0 && w.OldWeight > 0:
		impact = types.ImpactBlocked
		reason = fmt.Sprintf("weight dropped to 0 for %s/%s (was %d)",
			w.Host, w.Subset, w.OldWeight)
	case w.OldWeight == 0 && w.NewWeight > 0:
		// New subset coming online. If it has a known high error rate,
		// flag as DEGRADED; otherwise just REROUTED.
		if health.ErrorRate > 0.05 {
			impact = types.ImpactDegraded
			reason = fmt.Sprintf("introducing subset %s at weight %d with observed error rate %.1f%%",
				w.Subset, w.NewWeight, health.ErrorRate*100)
		} else {
			impact = types.ImpactRerouted
			reason = fmt.Sprintf("new subset %s added at weight %d", w.Subset, w.NewWeight)
		}
	default:
		// Weight changed but both old and new are > 0.
		if health.ErrorRate > 0.05 && w.NewWeight > w.OldWeight {
			impact = types.ImpactDegraded
			reason = fmt.Sprintf("weight shift %d → %d to subset %s with %.1f%% error rate",
				w.OldWeight, w.NewWeight, w.Subset, health.ErrorRate*100)
		} else {
			impact = types.ImpactRerouted
			reason = fmt.Sprintf("weight shift %s/%s: %d → %d",
				w.Host, w.Subset, w.OldWeight, w.NewWeight)
		}
	}

	return types.AffectedResource{
		Kind:       "Workload",
		Namespace:  "",
		Name:       w.Host + "/" + w.Subset,
		ImpactType: impact,
		Reason:     reason,
		Evidence: map[string]interface{}{
			"route_name":    w.RouteName,
			"host":          w.Host,
			"subset":        w.Subset,
			"old_weight":    w.OldWeight,
			"new_weight":    w.NewWeight,
			"total_rps":     totalRPS,
			"subset_rps":    health.RPS,
			"subset_errors": health.ErrorRate,
		},
	}
}

// destinationChangeToResource describes a wholesale host swap.
func destinationChangeToResource(d destinationChange, totalRPS float64) types.AffectedResource {
	return types.AffectedResource{
		Kind:       "Workload",
		Namespace:  "",
		Name:       d.Host,
		ImpactType: types.ImpactRerouted,
		Reason: fmt.Sprintf("destination changed: %s → %s (for route %s)",
			d.OldHost, d.Host, orDefault(d.MatchDesc, d.RouteName)),
		Evidence: map[string]interface{}{
			"route_name":     d.RouteName,
			"old_host":       d.OldHost,
			"new_host":       d.Host,
			"match":          d.MatchDesc,
			"old_host_rps":   totalRPS,
		},
	}
}

// routeRemovalToResource flags a match clause that disappeared. We can't know
// whether traffic previously hitting that match has a fallback without checking
// the default route, so we surface it as AT_RISK for the agent to reason about.
func routeRemovalToResource(r removedRoute) types.AffectedResource {
	return types.AffectedResource{
		Kind:       "Route",
		Namespace:  "",
		Name:       orDefault(r.RouteName, matchDescription(r.Match)),
		ImpactType: types.ImpactAtRisk,
		Reason: fmt.Sprintf("route removed: %s — traffic previously matching this clause will fall through",
			orDefault(r.RouteName, matchDescription(r.Match))),
		Evidence: map[string]interface{}{
			"removed_match": r.Match,
			"summary":       r.Summary,
		},
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func collectAllHosts(a, b *virtualServiceSpec) []string {
	seen := map[string]struct{}{}
	add := func(vs *virtualServiceSpec) {
		if vs == nil {
			return
		}
		for _, r := range vs.HTTP {
			for _, d := range r.Routes {
				if d.Host != "" {
					seen[d.Host] = struct{}{}
				}
			}
		}
		for _, r := range vs.TCP {
			for _, d := range r.Routes {
				if d.Host != "" {
					seen[d.Host] = struct{}{}
				}
			}
		}
	}
	add(a)
	add(b)

	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	return out
}

func uniqueHosts(routes []weightedRoute) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range routes {
		if _, ok := seen[r.Host]; !ok {
			seen[r.Host] = struct{}{}
			out = append(out, r.Host)
		}
	}
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]struct{}{}
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, x := range b {
		if _, ok := set[x]; !ok {
			return false
		}
	}
	return true
}

func stringMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func retriesEqual(a, b *retryPolicy) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Attempts == b.Attempts && a.PerTryTimeout == b.PerTryTimeout && a.RetryOn == b.RetryOn
}

func describeRetries(r *retryPolicy) string {
	if r == nil {
		return "<none>"
	}
	return fmt.Sprintf("attempts=%d per-try=%s on=%s", r.Attempts, r.PerTryTimeout, r.RetryOn)
}

// describeRoute produces a short human summary for diff entries.
func describeRoute(r httpRoute) string {
	parts := []string{}
	if len(r.Match) > 0 {
		parts = append(parts, "match=["+matchDescription(r.Match)+"]")
	}
	if len(r.Routes) > 0 {
		dests := make([]string, 0, len(r.Routes))
		for _, d := range r.Routes {
			if d.Subset != "" {
				dests = append(dests, fmt.Sprintf("%s/%s:%d", d.Host, d.Subset, d.Weight))
			} else {
				dests = append(dests, fmt.Sprintf("%s:%d", d.Host, d.Weight))
			}
		}
		parts = append(parts, "routes=["+strings.Join(dests, ",")+"]")
	}
	if r.Timeout != "" {
		parts = append(parts, "timeout="+r.Timeout)
	}
	return strings.Join(parts, " ")
}

// matchDescription creates a short readable string for a slice of match clauses.
func matchDescription(matches []routeMatch) string {
	if len(matches) == 0 {
		return "<any>"
	}
	parts := []string{}
	for _, m := range matches {
		var bits []string
		if m.URI != "" {
			bits = append(bits, "uri="+m.URI)
		}
		if m.Method != "" {
			bits = append(bits, "method="+m.Method)
		}
		if m.Port > 0 {
			bits = append(bits, fmt.Sprintf("port=%d", m.Port))
		}
		if len(m.Headers) > 0 {
			hparts := []string{}
			for k, v := range m.Headers {
				hparts = append(hparts, k+"="+v)
			}
			bits = append(bits, "headers={"+strings.Join(hparts, ",")+"}")
		}
		if len(bits) == 0 {
			bits = append(bits, "<any>")
		}
		parts = append(parts, strings.Join(bits, " "))
	}
	return strings.Join(parts, " OR ")
}

func orDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// addVSContextHints surfaces spec features that complicate static analysis or
// indicate risk, so the AI agent can factor them into confidence/severity.
func addVSContextHints(out *types.AnalyzerOutput, proposed *virtualServiceSpec, diff virtualServiceDiff) {
	if proposed.HasTLS {
		out.ContextHints = append(out.ContextHints,
			"Spec includes TLS routes; TLS route diffing is not yet implemented.")
	}
	if len(proposed.TCP) > 0 {
		out.ContextHints = append(out.ContextHints,
			"Spec includes TCP routes; TCP traffic impact is reported via diff only (no per-path metrics).")
	}
	if len(diff.HostChanges) > 0 {
		out.ContextHints = append(out.ContextHints, diff.HostChanges...)
	}
	if len(diff.PolicyAdditions) > 0 {
		out.ContextHints = append(out.ContextHints,
			fmt.Sprintf("%d policy attribute changes detected (timeout/retries/fault/mirror/redirect/rewrite): %s",
				len(diff.PolicyAdditions), strings.Join(diff.PolicyAdditions, "; ")))
	}
	if len(diff.AddedRoutes) > 0 {
		out.ContextHints = append(out.ContextHints,
			fmt.Sprintf("%d new route(s) added", len(diff.AddedRoutes)))
	}
	// Summary line — gives the agent a quick rollup.
	out.ContextHints = append(out.ContextHints, fmt.Sprintf(
		"Diff summary: %d weight shift(s), %d destination change(s), %d removed route(s), %d added route(s).",
		len(diff.WeightShifts), len(diff.DestinationChanges),
		len(diff.RemovedRoutes), len(diff.AddedRoutes)))
}
