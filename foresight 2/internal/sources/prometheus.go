package sources

import (
	"context"
	"fmt"
	"net/url"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"foresight/pkg/types"
)

// PromConnectionMode describes how we connect to Prometheus.
// These correspond to the CLI flags the user can provide.
type PromConnectionMode string

const (
	// PromModeDirect: explicit URL via --prometheus-url flag.
	PromModeDirect PromConnectionMode = "direct"
	// PromModePortForward: user has already port-forwarded; we hit localhost:<port>.
	PromModePortForward PromConnectionMode = "port-forward"
	// PromModeAutoDetect: scan common service names in the monitoring namespace.
	PromModeAutoDetect PromConnectionMode = "auto-detect"
)

// PromConfig controls how the client connects to Prometheus.
type PromConfig struct {
	Mode    PromConnectionMode
	URL     string        // used for Direct and PortForward modes
	Timeout time.Duration // per-query timeout; defaults to 30s
	// Auto-detect options (only used when Mode == PromModeAutoDetect)
	K8sClient             *K8sClient
	AutoDetectNamespaces  []string // defaults to ["monitoring", "istio-system", "prometheus"]
	AutoDetectServiceName []string // defaults to common prometheus service names
}

// PromClient is the concrete implementation of types.PrometheusClient.
type PromClient struct {
	api     promv1.API
	baseURL string
	timeout time.Duration
}

// NewPromClient constructs a PromClient based on the configured connection mode.
//
// Modes:
//   - Direct: uses cfg.URL verbatim.
//   - PortForward: expects a URL like http://localhost:9090 (same as Direct, but
//     semantically signals the user initiated a port-forward first).
//   - AutoDetect: locates a Prometheus service in common namespaces via the
//     K8s client and constructs a URL. Requires K8sClient.
func NewPromClient(ctx context.Context, cfg PromConfig) (*PromClient, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	baseURL, err := resolvePromURL(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve prometheus url: %w", err)
	}

	// Validate URL shape before handing to the client lib.
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid prometheus url %q: %w", baseURL, err)
	}

	client, err := promapi.NewClient(promapi.Config{Address: baseURL})
	if err != nil {
		return nil, fmt.Errorf("create prometheus client: %w", err)
	}

	return &PromClient{
		api:     promv1.NewAPI(client),
		baseURL: baseURL,
		timeout: timeout,
	}, nil
}

// resolvePromURL picks the right URL based on the connection mode.
func resolvePromURL(ctx context.Context, cfg PromConfig) (string, error) {
	switch cfg.Mode {
	case PromModeDirect, PromModePortForward:
		if cfg.URL == "" {
			return "", fmt.Errorf("%s mode requires URL", cfg.Mode)
		}
		return cfg.URL, nil

	case PromModeAutoDetect:
		if cfg.K8sClient == nil {
			return "", fmt.Errorf("auto-detect mode requires a K8sClient")
		}
		return autoDetectProm(ctx, cfg)

	default:
		return "", fmt.Errorf("unknown prometheus connection mode: %q", cfg.Mode)
	}
}

// autoDetectProm looks for a Prometheus service in common namespaces.
// It returns an in-cluster URL (only usable if Foresight itself runs in-cluster),
// which is fine for the eventual operator deployment. For local CLI usage
// users should prefer PortForward or Direct.
func autoDetectProm(ctx context.Context, cfg PromConfig) (string, error) {
	namespaces := cfg.AutoDetectNamespaces
	if len(namespaces) == 0 {
		namespaces = []string{"monitoring", "istio-system", "prometheus"}
	}
	serviceNames := cfg.AutoDetectServiceName
	if len(serviceNames) == 0 {
		serviceNames = []string{"prometheus-k8s", "kube-prometheus-stack-prometheus", "prometheus-server", "prometheus"}
	}

	for _, ns := range namespaces {
		svcs, err := cfg.K8sClient.ListServices(ctx, ns)
		if err != nil {
			continue
		}
		for _, svc := range svcs {
			for _, want := range serviceNames {
				if svc.Name != want {
					continue
				}
				port := pickPromPort(svc)
				if port == 0 {
					continue
				}
				return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, port), nil
			}
		}
	}
	return "", fmt.Errorf("could not auto-detect prometheus service in namespaces %v", namespaces)
}

// pickPromPort chooses the most likely Prometheus port from a Service.
// Preference order: named "web" or "http-web", port 9090, else the first port.
func pickPromPort(svc types.ServiceInfo) int32 {
	if len(svc.Ports) == 0 {
		return 0
	}
	for _, p := range svc.Ports {
		if p.Name == "web" || p.Name == "http-web" {
			return p.Port
		}
	}
	for _, p := range svc.Ports {
		if p.Port == 9090 {
			return p.Port
		}
	}
	return svc.Ports[0].Port
}

// Healthy verifies the Prometheus instance is reachable and responsive.
//
// We use a trivial instant query ("vector(1)") instead of the admin endpoints
// (e.g., Runtimeinfo) because the admin API is sometimes restricted in
// managed Prometheus deployments, and "vector(1)" works against any compliant
// PromQL endpoint — including Thanos, Cortex, and Grafana's PromQL proxy.
func (c *PromClient) Healthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, _, err := c.api.Query(ctx, "vector(1)", time.Now())
	return err
}

// Query runs an instant PromQL query and returns a normalized result.
func (c *PromClient) Query(ctx context.Context, query string) (types.QueryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	val, warnings, err := c.api.Query(ctx, query, time.Now())
	if err != nil {
		return types.QueryResult{}, fmt.Errorf("prometheus query failed: %w", err)
	}
	_ = warnings // TODO: surface these via a logger

	return convertPromValue(val), nil
}

// convertPromValue translates a Prometheus model value into our QueryResult type.
func convertPromValue(val model.Value) types.QueryResult {
	var result types.QueryResult
	switch v := val.(type) {
	case model.Vector:
		for _, s := range v {
			result.Series = append(result.Series, types.Series{
				Labels: labelsToMap(s.Metric),
				Samples: []types.Sample{{
					Timestamp: s.Timestamp.Time(),
					Value:     float64(s.Value),
				}},
			})
		}
	case model.Matrix:
		for _, ss := range v {
			samples := make([]types.Sample, 0, len(ss.Values))
			for _, pair := range ss.Values {
				samples = append(samples, types.Sample{
					Timestamp: pair.Timestamp.Time(),
					Value:     float64(pair.Value),
				})
			}
			result.Series = append(result.Series, types.Series{
				Labels:  labelsToMap(ss.Metric),
				Samples: samples,
			})
		}
	case *model.Scalar:
		result.Series = []types.Series{{
			Labels:  map[string]string{},
			Samples: []types.Sample{{Timestamp: v.Timestamp.Time(), Value: float64(v.Value)}},
		}}
	}
	return result
}

func labelsToMap(m model.Metric) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[string(k)] = string(v)
	}
	return out
}
