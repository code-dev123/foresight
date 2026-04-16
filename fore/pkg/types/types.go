// Package types defines the core data structures used throughout Foresight.
// These types form the contract between the parser, analyzers, collector,
// and downstream consumers (AI agent, dashboard, etc.).
package types

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// -----------------------------------------------------------------------------
// Identification
// -----------------------------------------------------------------------------

// GVK identifies a Kubernetes resource kind.
type GVK struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// String returns "group/version/Kind" or "core/version/Kind" if no group.
func (g GVK) String() string {
	if g.Group == "" {
		return "core/" + g.Version + "/" + g.Kind
	}
	return g.Group + "/" + g.Version + "/" + g.Kind
}

// Matches returns true if the other GVK has the same group, version, and kind.
func (g GVK) Matches(other GVK) bool {
	return g.Group == other.Group && g.Version == other.Version && g.Kind == other.Kind
}

// Operation describes what the user intends to do with the resource.
type Operation string

const (
	OpCreate Operation = "CREATE"
	OpUpdate Operation = "UPDATE"
	OpDelete Operation = "DELETE"
)

// ImpactType categorizes how a resource is affected by a proposed change.
// This is standardized across analyzers so the AI agent can reason uniformly.
type ImpactType string

const (
	ImpactBlocked  ImpactType = "BLOCKED"  // traffic/access fully denied
	ImpactDegraded ImpactType = "DEGRADED" // partially affected but still works
	ImpactRerouted ImpactType = "REROUTED" // traffic redirected to different target
	ImpactLimited  ImpactType = "LIMITED"  // throttled, capped, or throttled
	ImpactDenied   ImpactType = "DENIED"   // permission/access removed
	ImpactAtRisk   ImpactType = "AT_RISK"  // headroom concern, not yet broken
)

// -----------------------------------------------------------------------------
// Input: what the user submitted
// -----------------------------------------------------------------------------

// ProposedChange is the normalized form of a user-submitted config change.
type ProposedChange struct {
	Operation    Operation                  `json:"operation"`
	GVK          GVK                        `json:"gvk"`
	Namespace    string                     `json:"namespace"`
	Name         string                     `json:"name"`
	RawYAML      string                     `json:"raw_yaml"`
	Parsed       *unstructured.Unstructured `json:"-"` // full parsed object
	CurrentState *unstructured.Unstructured `json:"-"` // live state if UPDATE/DELETE
}

// -----------------------------------------------------------------------------
// Analyzer output: standardized shape every analyzer produces
// -----------------------------------------------------------------------------

// AffectedResource describes a resource impacted by a proposed change.
// This structure is cross-analyzer standardized — the AI agent and downstream
// consumers rely on it regardless of which analyzer produced the output.
type AffectedResource struct {
	Kind       string                 `json:"kind"`
	Namespace  string                 `json:"namespace"`
	Name       string                 `json:"name"`
	ImpactType ImpactType             `json:"impact_type"`
	Reason     string                 `json:"reason"`   // short human-readable explanation
	Evidence   map[string]interface{} `json:"evidence"` // analyzer-specific proof
}

// AnalyzerOutput is the standardized output every analyzer produces.
// LiveData is deliberately a map because each analyzer's data shape differs
// (Istio has traffic edges, ResourceQuota has pod usage, etc.).
// AffectedResources is the standardized cross-analyzer contract.
type AnalyzerOutput struct {
	AnalyzerName      string                 `json:"analyzer_name"`
	CollectedAt       time.Time              `json:"collected_at"`
	DurationMS        int64                  `json:"duration_ms"`
	AffectedResources []AffectedResource     `json:"affected_resources"`
	ContextHints      []string               `json:"context_hints,omitempty"`
	LiveData          map[string]interface{} `json:"live_data,omitempty"`
	DataSourceStatus  map[string]string      `json:"data_source_status,omitempty"`
}

// -----------------------------------------------------------------------------
// Final output: the full cluster snapshot
// -----------------------------------------------------------------------------

// SnapshotMetadata carries info about how and when the snapshot was produced.
type SnapshotMetadata struct {
	SchemaVersion    string    `json:"schema_version"`
	GeneratedAt      time.Time `json:"generated_at"`
	GeneratedBy      string    `json:"generated_by"`
	ClusterContext   string    `json:"cluster_context,omitempty"`
	CollectionTimeMS int64     `json:"collection_time_ms"`
}

// CollectionError captures non-fatal errors during collection so they surface
// in the output instead of being swallowed silently.
type CollectionError struct {
	Component string `json:"component"`
	Message   string `json:"message"`
}

// ClusterSnapshot is the final output of the data collector. This is what
// gets handed to the AI agent for impact analysis.
type ClusterSnapshot struct {
	Metadata         SnapshotMetadata  `json:"metadata"`
	ProposedChange   ProposedChange    `json:"proposed_change"`
	AnalyzerOutputs  []AnalyzerOutput  `json:"analyzer_outputs"`
	CollectionErrors []CollectionError `json:"collection_errors,omitempty"`
}

// -----------------------------------------------------------------------------
// Data sources: bundled clients analyzers use
// -----------------------------------------------------------------------------

// K8sClient is the subset of Kubernetes API operations analyzers need.
// Kept as an interface so we can mock it in tests.
type K8sClient interface {
	ListPods(ctx context.Context, namespace string, labelSelector string) ([]PodInfo, error)
	ListServices(ctx context.Context, namespace string) ([]ServiceInfo, error)
	GetResource(ctx context.Context, gvk GVK, namespace, name string) (*unstructured.Unstructured, error)
	ListResources(ctx context.Context, gvk GVK, namespace string) ([]unstructured.Unstructured, error)
}

// PrometheusClient executes PromQL queries.
type PrometheusClient interface {
	Query(ctx context.Context, query string) (QueryResult, error)
	Healthy(ctx context.Context) error
}

// MetricsClient pulls pod/container resource usage from metrics-server.
type MetricsClient interface {
	PodUsage(ctx context.Context, namespace string) ([]PodMetric, error)
}

// DataSources bundles the clients an analyzer might use.
// Any client may be nil if unavailable — analyzers must handle that gracefully
// and report the fact via DataSourceStatus in their output.
type DataSources struct {
	K8s        K8sClient
	Prometheus PrometheusClient
	Metrics    MetricsClient
}

// -----------------------------------------------------------------------------
// Data transfer objects for data source results
// -----------------------------------------------------------------------------

// PodInfo is a lightweight view of a Pod — just what analyzers need.
type PodInfo struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Labels         map[string]string `json:"labels"`
	ServiceAccount string            `json:"service_account"`
	NodeName       string            `json:"node_name,omitempty"`
	Phase          string            `json:"phase"`
}

// ServiceInfo is a lightweight view of a Service.
type ServiceInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Selector  map[string]string `json:"selector"`
	Ports     []ServicePort     `json:"ports"`
}

// ServicePort describes a single port on a Service.
type ServicePort struct {
	Name       string `json:"name"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port"`
	Protocol   string `json:"protocol"`
}

// PodMetric carries current resource usage for a pod.
type PodMetric struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	CPUMilli    int64  `json:"cpu_milli"`
	MemoryBytes int64  `json:"memory_bytes"`
}

// QueryResult is the common shape returned from PromQL queries.
// For vector queries each Series has one Sample; for range queries, many.
type QueryResult struct {
	Series []Series `json:"series"`
}

// Series is one labeled time series.
type Series struct {
	Labels  map[string]string `json:"labels"`
	Samples []Sample          `json:"samples"`
}

// Sample is a single (timestamp, value) data point.
type Sample struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}
