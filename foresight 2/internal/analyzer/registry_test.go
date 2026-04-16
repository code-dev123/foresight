package analyzer

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"foresight/pkg/types"
)

// fakeAnalyzer is a minimal Analyzer implementation for testing the registry.
type fakeAnalyzer struct {
	name  string
	kinds []types.GVK
	canFn func(*unstructured.Unstructured) bool
}

func (f *fakeAnalyzer) Name() string               { return f.name }
func (f *fakeAnalyzer) SupportedKinds() []types.GVK { return f.kinds }
func (f *fakeAnalyzer) CanAnalyze(r *unstructured.Unstructured) bool {
	if f.canFn != nil {
		return f.canFn(r)
	}
	return true
}
func (f *fakeAnalyzer) Collect(ctx context.Context, c *types.ProposedChange, s *types.DataSources) (*types.AnalyzerOutput, error) {
	return &types.AnalyzerOutput{AnalyzerName: f.name}, nil
}

func TestRegister_DuplicateName(t *testing.T) {
	reg := NewRegistry()
	a := &fakeAnalyzer{name: "dup"}

	if err := reg.Register(a); err != nil {
		t.Fatalf("first register should succeed: %v", err)
	}
	if err := reg.Register(a); err == nil {
		t.Fatal("second register with same name should fail")
	}
}

func TestRegister_NilAnalyzer(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(nil); err == nil {
		t.Fatal("registering nil analyzer should fail")
	}
}

func TestRegister_EmptyName(t *testing.T) {
	reg := NewRegistry()
	a := &fakeAnalyzer{name: ""}
	if err := reg.Register(a); err == nil {
		t.Fatal("analyzer with empty name should be rejected")
	}
}

func TestFind_MatchesGVK(t *testing.T) {
	reg := NewRegistry()
	istioGVK := types.GVK{Group: "security.istio.io", Version: "v1", Kind: "AuthorizationPolicy"}
	netpolGVK := types.GVK{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}

	a1 := &fakeAnalyzer{name: "a1", kinds: []types.GVK{istioGVK}}
	a2 := &fakeAnalyzer{name: "a2", kinds: []types.GVK{netpolGVK}}
	if err := reg.Register(a1); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(a2); err != nil {
		t.Fatal(err)
	}

	got := reg.Find(istioGVK, &unstructured.Unstructured{})
	if len(got) != 1 || got[0].Name() != "a1" {
		t.Fatalf("expected a1 for istio gvk, got %d results", len(got))
	}

	got = reg.Find(netpolGVK, &unstructured.Unstructured{})
	if len(got) != 1 || got[0].Name() != "a2" {
		t.Fatalf("expected a2 for netpol gvk, got %d results", len(got))
	}

	// Unknown GVK — no matches.
	unknown := types.GVK{Group: "foo", Version: "v1", Kind: "Bar"}
	if got := reg.Find(unknown, &unstructured.Unstructured{}); len(got) != 0 {
		t.Fatalf("expected 0 results for unknown GVK, got %d", len(got))
	}
}

func TestFind_CanAnalyzeFilter(t *testing.T) {
	reg := NewRegistry()
	gvk := types.GVK{Group: "g", Version: "v1", Kind: "K"}

	yes := &fakeAnalyzer{name: "yes", kinds: []types.GVK{gvk}, canFn: func(*unstructured.Unstructured) bool { return true }}
	no := &fakeAnalyzer{name: "no", kinds: []types.GVK{gvk}, canFn: func(*unstructured.Unstructured) bool { return false }}
	_ = reg.Register(yes)
	_ = reg.Register(no)

	got := reg.Find(gvk, &unstructured.Unstructured{})
	if len(got) != 1 || got[0].Name() != "yes" {
		t.Fatalf("expected only 'yes' to be returned, got %d", len(got))
	}
}

func TestGVK_Matches(t *testing.T) {
	a := types.GVK{Group: "g", Version: "v1", Kind: "K"}
	b := types.GVK{Group: "g", Version: "v1", Kind: "K"}
	c := types.GVK{Group: "g", Version: "v2", Kind: "K"}

	if !a.Matches(b) {
		t.Fatal("identical GVKs should match")
	}
	if a.Matches(c) {
		t.Fatal("different versions should not match")
	}
}
