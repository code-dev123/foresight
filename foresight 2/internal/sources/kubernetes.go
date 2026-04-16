// Package sources provides concrete implementations of the data source
// interfaces defined in pkg/types. Analyzers receive these via DataSources
// and should use them through the interface — not the concrete types — to
// remain testable.
package sources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"foresight/pkg/types"
)

// K8sClient is a concrete implementation of types.K8sClient.
// It wraps client-go with a thinner API surface tailored to what analyzers need.
type K8sClient struct {
	typed   kubernetes.Interface
	dynamic dynamic.Interface
}

// NewK8sClient builds a client from the standard kubeconfig resolution order:
//  1. In-cluster config (when running inside a pod)
//  2. KUBECONFIG environment variable
//  3. ~/.kube/config
func NewK8sClient() (*K8sClient, error) {
	config, err := loadKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	typed, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create typed client: %w", err)
	}

	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}

	return &K8sClient{typed: typed, dynamic: dyn}, nil
}

func loadKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first.
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	// Fall back to kubeconfig file.
	path := os.Getenv("KUBECONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir: %w", err)
		}
		path = filepath.Join(home, ".kube", "config")
	}

	return clientcmd.BuildConfigFromFlags("", path)
}

// ListPods returns pods matching the optional label selector.
// Pass an empty string to list all pods in the namespace.
func (c *K8sClient) ListPods(ctx context.Context, namespace, labelSelector string) ([]types.PodInfo, error) {
	pods, err := c.typed.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("list pods in %s: %w", namespace, err)
	}

	out := make([]types.PodInfo, 0, len(pods.Items))
	for _, p := range pods.Items {
		out = append(out, types.PodInfo{
			Name:           p.Name,
			Namespace:      p.Namespace,
			Labels:         p.Labels,
			ServiceAccount: p.Spec.ServiceAccountName,
			NodeName:       p.Spec.NodeName,
			Phase:          string(p.Status.Phase),
		})
	}
	return out, nil
}

// ListServices returns services in a namespace.
func (c *K8sClient) ListServices(ctx context.Context, namespace string) ([]types.ServiceInfo, error) {
	svcs, err := c.typed.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services in %s: %w", namespace, err)
	}

	out := make([]types.ServiceInfo, 0, len(svcs.Items))
	for _, s := range svcs.Items {
		out = append(out, types.ServiceInfo{
			Name:      s.Name,
			Namespace: s.Namespace,
			Selector:  s.Spec.Selector,
			Ports:     mapPorts(s.Spec.Ports),
		})
	}
	return out, nil
}

func mapPorts(ports []corev1.ServicePort) []types.ServicePort {
	out := make([]types.ServicePort, 0, len(ports))
	for _, p := range ports {
		out = append(out, types.ServicePort{
			Name:       p.Name,
			Port:       p.Port,
			TargetPort: p.TargetPort.String(),
			Protocol:   string(p.Protocol),
		})
	}
	return out
}

// GetResource fetches a single resource by GVK + namespace + name.
// Uses the dynamic client so it works for CRDs (e.g., Istio AuthorizationPolicy).
// Returns (nil, nil) if the resource doesn't exist — callers should check
// both the error and the returned object.
func (c *K8sClient) GetResource(ctx context.Context, gvk types.GVK, namespace, name string) (*unstructured.Unstructured, error) {
	gvr := gvkToGVR(gvk)
	obj, err := c.dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// NOTE: for now, any error is returned. Callers that want "does not exist"
		// handling can inspect the error; we can refine with apierrors.IsNotFound later.
		return nil, err
	}
	return obj, nil
}

// ListResources returns all resources of a given GVK in a namespace.
func (c *K8sClient) ListResources(ctx context.Context, gvk types.GVK, namespace string) ([]unstructured.Unstructured, error) {
	gvr := gvkToGVR(gvk)
	list, err := c.dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list %s in %s: %w", gvk.String(), namespace, err)
	}
	return list.Items, nil
}

// gvkToGVR converts a GVK to a GroupVersionResource using a simple
// pluralization rule. Sufficient for our initial analyzers. For full
// correctness we'd use a RESTMapper, but that's a dependency we don't need yet.
func gvkToGVR(gvk types.GVK) schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: pluralize(gvk.Kind),
	}
}

// pluralize applies a very simple pluralization heuristic.
// Covers the cases we care about (Pod -> pods, Policy -> policies, etc.).
// Replace with a RESTMapper lookup if this proves insufficient.
func pluralize(kind string) string {
	lower := toLower(kind)
	switch {
	case hasSuffix(lower, "y"):
		return lower[:len(lower)-1] + "ies"
	case hasSuffix(lower, "s"), hasSuffix(lower, "x"), hasSuffix(lower, "z"),
		hasSuffix(lower, "ch"), hasSuffix(lower, "sh"):
		return lower + "es"
	default:
		return lower + "s"
	}
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
