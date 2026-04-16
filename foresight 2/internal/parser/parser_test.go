package parser

import (
	"context"
	"testing"

	"foresight/pkg/types"
)

const sampleAuthPolicy = `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: restrict-checkout
  namespace: payments
spec:
  selector:
    matchLabels:
      app: checkout
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/frontend/sa/web"]
`

func TestParse_AuthorizationPolicy(t *testing.T) {
	p := New(nil) // no K8s client — parser should still work in dry-parse mode
	change, err := p.Parse(context.Background(), []byte(sampleAuthPolicy))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if change.GVK.Group != "security.istio.io" {
		t.Errorf("expected group 'security.istio.io', got %q", change.GVK.Group)
	}
	if change.GVK.Version != "v1" {
		t.Errorf("expected version 'v1', got %q", change.GVK.Version)
	}
	if change.GVK.Kind != "AuthorizationPolicy" {
		t.Errorf("expected kind 'AuthorizationPolicy', got %q", change.GVK.Kind)
	}
	if change.Namespace != "payments" {
		t.Errorf("expected namespace 'payments', got %q", change.Namespace)
	}
	if change.Name != "restrict-checkout" {
		t.Errorf("expected name 'restrict-checkout', got %q", change.Name)
	}
	// Without a K8s client we cannot determine UPDATE vs CREATE — default is CREATE.
	if change.Operation != types.OpCreate {
		t.Errorf("expected operation CREATE in dry-parse mode, got %q", change.Operation)
	}
	if change.Parsed == nil {
		t.Error("expected Parsed to be populated")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	p := New(nil)
	if _, err := p.Parse(context.Background(), []byte{}); err == nil {
		t.Fatal("empty input should return an error")
	}
}

func TestParse_MissingKind(t *testing.T) {
	p := New(nil)
	yaml := `
apiVersion: v1
metadata:
  name: foo
`
	if _, err := p.Parse(context.Background(), []byte(yaml)); err == nil {
		t.Fatal("YAML without kind should return an error")
	}
}

func TestDescribe(t *testing.T) {
	change := &types.ProposedChange{
		Operation: types.OpCreate,
		GVK:       types.GVK{Kind: "AuthorizationPolicy"},
		Namespace: "payments",
		Name:      "restrict-checkout",
	}
	got := Describe(change)
	want := "CREATE AuthorizationPolicy payments/restrict-checkout"
	if got != want {
		t.Errorf("Describe() = %q, want %q", got, want)
	}
}
