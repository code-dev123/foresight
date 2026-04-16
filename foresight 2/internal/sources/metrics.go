package sources

import (
	"context"
	"fmt"

	"foresight/pkg/types"
)

// MetricsClient is a placeholder for the metrics-server integration.
//
// The ResourceQuota analyzer will need pod-level CPU/memory usage data
// to predict OOMKill risk when a quota change squeezes headroom. The
// metrics-server API (metrics.k8s.io/v1beta1) exposes exactly that.
//
// For the initial milestone we leave this as a stub that returns a clear
// "not implemented" error. Analyzers that attempt to use it will report
// missing data in their DataSourceStatus, which is the intended behavior
// during development.
type MetricsClient struct{}

// NewMetricsClient returns a stub metrics client.
func NewMetricsClient() *MetricsClient {
	return &MetricsClient{}
}

// PodUsage returns current CPU/memory usage for pods in a namespace.
//
// TODO(resourcequota-analyzer): implement using the metrics.k8s.io client:
//
//	import metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
//	client, _ := metricsv.NewForConfig(restConfig)
//	list, _ := client.MetricsV1beta1().PodMetricses(ns).List(ctx, metav1.ListOptions{})
func (m *MetricsClient) PodUsage(ctx context.Context, namespace string) ([]types.PodMetric, error) {
	return nil, fmt.Errorf("metrics client not yet implemented")
}
