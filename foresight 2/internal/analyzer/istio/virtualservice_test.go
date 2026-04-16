package istio

import (
	"testing"
)

func TestDiffVS_CreateOperation_AllRoutesAdded(t *testing.T) {
	// No current state (CREATE) — every route is added.
	proposed := &virtualServiceSpec{
		Hosts: []string{"checkout.payments.svc.cluster.local"},
		HTTP: []httpRoute{
			{
				Name:   "primary",
				Routes: []weightedRoute{{Host: "checkout", Subset: "v1", Weight: 100}},
			},
		},
	}
	diff := diffVirtualServices(nil, proposed)

	if len(diff.AddedRoutes) != 1 {
		t.Fatalf("expected 1 added route, got %d", len(diff.AddedRoutes))
	}
	if len(diff.WeightShifts) != 0 {
		t.Errorf("expected 0 weight shifts on CREATE, got %d", len(diff.WeightShifts))
	}
}

func TestDiffVS_WeightShift_CanaryToFull(t *testing.T) {
	// Classic scenario: promoting v2 from 10% canary to 100%.
	current := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name: "primary",
			Routes: []weightedRoute{
				{Host: "checkout", Subset: "v1", Weight: 90},
				{Host: "checkout", Subset: "v2", Weight: 10},
			},
		}},
	}
	proposed := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name: "primary",
			Routes: []weightedRoute{
				{Host: "checkout", Subset: "v1", Weight: 0},
				{Host: "checkout", Subset: "v2", Weight: 100},
			},
		}},
	}
	diff := diffVirtualServices(current, proposed)

	if len(diff.WeightShifts) != 2 {
		t.Fatalf("expected 2 weight shifts, got %d", len(diff.WeightShifts))
	}

	// Verify both shifts are represented correctly.
	shifts := map[string]weightShift{}
	for _, w := range diff.WeightShifts {
		shifts[w.Subset] = w
	}
	if shifts["v1"].OldWeight != 90 || shifts["v1"].NewWeight != 0 {
		t.Errorf("v1 shift wrong: got old=%d new=%d, want 90→0",
			shifts["v1"].OldWeight, shifts["v1"].NewWeight)
	}
	if shifts["v2"].OldWeight != 10 || shifts["v2"].NewWeight != 100 {
		t.Errorf("v2 shift wrong: got old=%d new=%d, want 10→100",
			shifts["v2"].OldWeight, shifts["v2"].NewWeight)
	}
}

func TestDiffVS_SubsetRemoved_WeightsTo0(t *testing.T) {
	current := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:   "primary",
			Routes: []weightedRoute{{Host: "checkout", Subset: "v1", Weight: 100}},
		}},
	}
	proposed := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:   "primary",
			Routes: []weightedRoute{{Host: "checkout", Subset: "v2", Weight: 100}},
		}},
	}
	diff := diffVirtualServices(current, proposed)

	// v1 dropped out entirely and v2 appeared — 2 weight shifts.
	if len(diff.WeightShifts) != 2 {
		t.Fatalf("expected 2 shifts (v1 removed, v2 added), got %d", len(diff.WeightShifts))
	}

	// Same host but different subsets — no host-level destination change.
	if len(diff.DestinationChanges) != 0 {
		t.Errorf("same host, different subsets should not produce a destination change, got %d",
			len(diff.DestinationChanges))
	}
}

func TestDiffVS_DestinationHostSwap(t *testing.T) {
	// Entire host swapped — classic "deploy of new service" scenario.
	current := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:   "primary",
			Routes: []weightedRoute{{Host: "checkout-old", Weight: 100}},
		}},
	}
	proposed := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:   "primary",
			Routes: []weightedRoute{{Host: "checkout-new", Weight: 100}},
		}},
	}
	diff := diffVirtualServices(current, proposed)

	if len(diff.DestinationChanges) != 1 {
		t.Fatalf("expected 1 destination change, got %d", len(diff.DestinationChanges))
	}
}

func TestDiffVS_RouteRemoval(t *testing.T) {
	current := &virtualServiceSpec{
		HTTP: []httpRoute{
			{Name: "v2-only", Match: []routeMatch{{URI: "prefix:/api/v2"}}, Routes: []weightedRoute{{Host: "checkout", Subset: "v2", Weight: 100}}},
			{Name: "default", Routes: []weightedRoute{{Host: "checkout", Subset: "v1", Weight: 100}}},
		},
	}
	proposed := &virtualServiceSpec{
		HTTP: []httpRoute{
			// Only the default remains — v2-only is removed.
			{Name: "default", Routes: []weightedRoute{{Host: "checkout", Subset: "v1", Weight: 100}}},
		},
	}
	diff := diffVirtualServices(current, proposed)

	if len(diff.RemovedRoutes) != 1 {
		t.Fatalf("expected 1 removed route, got %d", len(diff.RemovedRoutes))
	}
	if diff.RemovedRoutes[0].RouteName != "v2-only" {
		t.Errorf("expected removed route 'v2-only', got %q", diff.RemovedRoutes[0].RouteName)
	}
}

func TestDiffVS_PolicyAdditions_TimeoutChange(t *testing.T) {
	current := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:    "primary",
			Timeout: "5s",
			Routes:  []weightedRoute{{Host: "checkout", Weight: 100}},
		}},
	}
	proposed := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:    "primary",
			Timeout: "30s", // bumped
			Routes:  []weightedRoute{{Host: "checkout", Weight: 100}},
		}},
	}
	diff := diffVirtualServices(current, proposed)

	if len(diff.PolicyAdditions) == 0 {
		t.Fatal("expected timeout change to be flagged as a policy addition")
	}
}

func TestDiffVS_NoChange_EmptyDiff(t *testing.T) {
	spec := &virtualServiceSpec{
		HTTP: []httpRoute{{
			Name:   "primary",
			Routes: []weightedRoute{{Host: "checkout", Subset: "v1", Weight: 100}},
		}},
	}
	diff := diffVirtualServices(spec, spec)

	if len(diff.WeightShifts) != 0 || len(diff.DestinationChanges) != 0 ||
		len(diff.RemovedRoutes) != 0 || len(diff.AddedRoutes) != 0 ||
		len(diff.PolicyAdditions) != 0 {
		t.Errorf("identical specs should produce empty diff, got %+v", diff)
	}
}

func TestWeightShiftToResource_DropToZero_IsBlocked(t *testing.T) {
	w := weightShift{Host: "checkout", Subset: "v1", OldWeight: 100, NewWeight: 0}
	got := weightShiftToResource(w, 150.0, nil)

	if got.ImpactType != "BLOCKED" {
		t.Errorf("weight drop to 0 should be BLOCKED, got %s", got.ImpactType)
	}
}

func TestWeightShiftToResource_HighErrorSubset_IsDegraded(t *testing.T) {
	w := weightShift{Host: "checkout", Subset: "v2", OldWeight: 10, NewWeight: 100}
	health := map[string]subsetMetric{
		"checkout/v2": {Host: "checkout", Subset: "v2", RPS: 100, ErrorRate: 0.40},
	}
	got := weightShiftToResource(w, 100.0, health)

	if got.ImpactType != "DEGRADED" {
		t.Errorf("shift up to high-error subset should be DEGRADED, got %s", got.ImpactType)
	}
}

func TestWeightShiftToResource_HealthySubset_IsRerouted(t *testing.T) {
	w := weightShift{Host: "checkout", Subset: "v2", OldWeight: 10, NewWeight: 50}
	health := map[string]subsetMetric{
		"checkout/v2": {Host: "checkout", Subset: "v2", RPS: 100, ErrorRate: 0.001},
	}
	got := weightShiftToResource(w, 100.0, health)

	if got.ImpactType != "REROUTED" {
		t.Errorf("shift to healthy subset should be REROUTED, got %s", got.ImpactType)
	}
}
