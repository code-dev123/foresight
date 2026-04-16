package istio

import "testing"

func TestPolicyPermits_AllowNoRules_DeniesAll(t *testing.T) {
	p := &authPolicySpec{Action: "ALLOW"}
	edge := trafficEdge{
		SourceWorkload:  "order-service",
		SourceNamespace: "orders",
		SourcePrincipal: "cluster.local/ns/orders/sa/order-service",
	}
	if policyPermits(p, edge) {
		t.Fatal("ALLOW policy with no rules should block all traffic")
	}
}

func TestPolicyPermits_MatchingPrincipal(t *testing.T) {
	p := &authPolicySpec{
		Action: "ALLOW",
		Rules: []authRule{
			{FromPrincipals: []string{"cluster.local/ns/orders/sa/order-service"}},
		},
	}
	edge := trafficEdge{
		SourcePrincipal: "cluster.local/ns/orders/sa/order-service",
	}
	if !policyPermits(p, edge) {
		t.Fatal("edge with matching principal should be permitted")
	}
}

func TestPolicyPermits_NonMatchingPrincipal(t *testing.T) {
	p := &authPolicySpec{
		Action: "ALLOW",
		Rules: []authRule{
			{FromPrincipals: []string{"cluster.local/ns/frontend/sa/web"}},
		},
	}
	edge := trafficEdge{
		SourcePrincipal: "cluster.local/ns/orders/sa/order-service",
	}
	if policyPermits(p, edge) {
		t.Fatal("edge with non-matching principal should be blocked")
	}
}

func TestPolicyPermits_WildcardPrincipal(t *testing.T) {
	p := &authPolicySpec{
		Action: "ALLOW",
		Rules:  []authRule{{FromPrincipals: []string{"*"}}},
	}
	edge := trafficEdge{SourcePrincipal: "anything"}
	if !policyPermits(p, edge) {
		t.Fatal("wildcard principal should permit any source")
	}
}

func TestPolicyPermits_WildcardSuffixPrincipal(t *testing.T) {
	p := &authPolicySpec{
		Action: "ALLOW",
		Rules:  []authRule{{FromPrincipals: []string{"cluster.local/ns/orders/*"}}},
	}
	if !policyPermits(p, trafficEdge{SourcePrincipal: "cluster.local/ns/orders/sa/order-service"}) {
		t.Fatal("suffix wildcard should match principals under the prefix")
	}
	if policyPermits(p, trafficEdge{SourcePrincipal: "cluster.local/ns/frontend/sa/web"}) {
		t.Fatal("suffix wildcard should not match principals outside the prefix")
	}
}

func TestPolicyPermits_NamespaceMatch(t *testing.T) {
	p := &authPolicySpec{
		Action: "ALLOW",
		Rules:  []authRule{{FromNamespaces: []string{"orders"}}},
	}
	if !policyPermits(p, trafficEdge{SourceNamespace: "orders"}) {
		t.Fatal("matching namespace should be permitted")
	}
	if policyPermits(p, trafficEdge{SourceNamespace: "frontend"}) {
		t.Fatal("non-matching namespace should be blocked")
	}
}

func TestPolicyPermits_EmptyRuleMatchesAll(t *testing.T) {
	// An ALLOW rule with no from-constraints matches anything.
	p := &authPolicySpec{
		Action: "ALLOW",
		Rules:  []authRule{{}},
	}
	if !policyPermits(p, trafficEdge{SourcePrincipal: "whatever"}) {
		t.Fatal("empty rule should permit any source")
	}
}

func TestPolicyPermits_NonAllowAction_DefersToAgent(t *testing.T) {
	// DENY/AUDIT/CUSTOM policies need AI reasoning; static analysis returns true
	// to avoid false positives in the "blocked" list.
	for _, action := range []string{"DENY", "AUDIT", "CUSTOM"} {
		p := &authPolicySpec{Action: action}
		if !policyPermits(p, trafficEdge{}) {
			t.Fatalf("action %q should defer to AI agent (return true)", action)
		}
	}
}
