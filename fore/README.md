# Foresight

> Predict the impact of a Kubernetes config change before you apply it.

Foresight is a data collector + analysis pipeline that takes a proposed config change, collects live cluster data relevant to it, and produces a standardized snapshot describing the change's impact. The snapshot is the input an AI agent reasons about to answer: **what will this change break?**

## Status

Stage 1 MVP — Data Collector only. Analyzers implemented:

- ✅ **Istio AuthorizationPolicy** — traffic blocking analysis via Prometheus
- 🔜 Istio VirtualService — routing change analysis
- 🔜 NetworkPolicy (standard + Cilium) — pod isolation analysis
- 🔜 ResourceQuota — capacity headroom analysis

## Quick start

```bash
# Build
make build

# List registered analyzers
./bin/foresight info

# Dry-parse a sample fixture (no cluster needed)
./bin/foresight analyze -f test/fixtures/istio-authpolicy.yaml --dry-parse

# Real analysis against your cluster (requires Istio + Prometheus)
./bin/foresight analyze -f my-change.yaml

# With explicit Prometheus URL (e.g. after port-forward)
./bin/foresight analyze -f my-change.yaml \
  --prometheus-url http://localhost:9090 \
  --prometheus-mode direct

# JSON output (for piping to the AI agent later)
./bin/foresight analyze -f my-change.yaml -o json
```

## Prometheus connection modes

Foresight supports three ways to reach Prometheus:

- `auto-detect` (default) — scans common namespaces for the Prometheus service. Works when Foresight runs in-cluster; not ideal for local CLI use.
- `direct` — uses `--prometheus-url` verbatim. Use this when you have a known reachable URL.
- `port-forward` — same as `direct` semantically; communicates intent. Pair with `kubectl port-forward svc/prometheus 9090:9090`.

If you pass `--prometheus-url` without `--prometheus-mode`, the tool automatically uses `direct` mode.

## Project layout

```
foresight/
├── cmd/foresight/            CLI entry point
├── internal/
│   ├── analyzer/             Plugin interface + registry
│   │   └── istio/            Istio analyzers
│   ├── collector/            Pipeline orchestrator
│   ├── parser/               YAML → ProposedChange
│   └── sources/              K8s, Prometheus, Metrics clients
├── pkg/types/                Shared type definitions
└── test/fixtures/            Sample YAMLs
```

## Adding a new analyzer

1. Create a new package under `internal/analyzer/<yourname>/`.
2. Implement the `analyzer.Analyzer` interface (see `internal/analyzer/interface.go`).
3. Register it in `buildRegistry()` inside `cmd/foresight/analyze.go`.

That's it — the parser, collector, and CLI require no changes.

## The snapshot schema

Running `foresight analyze -o json` produces a `ClusterSnapshot`:

```jsonc
{
  "metadata": {
    "schema_version": "0.1.0",
    "generated_at": "...",
    "collection_time_ms": 842
  },
  "proposed_change": {
    "operation": "CREATE",
    "gvk": {"group": "security.istio.io", "version": "v1", "kind": "AuthorizationPolicy"},
    "namespace": "payments",
    "name": "restrict-checkout"
  },
  "analyzer_outputs": [
    {
      "analyzer_name": "istio-authpolicy",
      "affected_resources": [
        {
          "kind": "Workload",
          "namespace": "orders",
          "name": "order-service",
          "impact_type": "BLOCKED",
          "reason": "Currently sending 200.0 RPS to payments/checkout; not permitted by proposed policy"
        }
      ],
      "context_hints": [...],
      "live_data": { /* analyzer-specific */ }
    }
  ]
}
```

`affected_resources` is the cross-analyzer standardized contract. `live_data` is analyzer-specific (shape varies).
