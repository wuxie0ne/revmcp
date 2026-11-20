package registry

import (
	"context"
	"testing"

	"github.com/revmcp/revmcp/proto"
)

type stubCaller struct {
	closed bool
}

func (s *stubCaller) Call(_ context.Context, _ string, _ any, _ any) error { return nil }
func (s *stubCaller) Close() error                                         { s.closed = true; return nil }

func TestRegistryReplaceAndStaleUnregister(t *testing.T) {
	t.Parallel()

	reg := New()
	c1 := &stubCaller{}
	c2 := &stubCaller{}

	e1, replaced := reg.Register(proto.AgentInfo{
		TargetID: "node-01",
		Mode:     proto.ModeReadOnly,
		Tags:     map[string]string{"env": "prod"},
	}, c1)
	if replaced != nil {
		t.Fatalf("expected no replaced entry on first register")
	}

	e2, replaced := reg.Register(proto.AgentInfo{
		TargetID: "node-01",
		Mode:     proto.ModeRestricted,
		Tags:     map[string]string{"env": "prod"},
	}, c2)
	if replaced == nil || replaced.Generation != e1.Generation {
		t.Fatalf("expected e1 to be replaced")
	}

	// Stale unregister from e1 must not remove e2.
	if reg.Unregister("node-01", e1.Generation) {
		t.Fatal("stale unregister must return false")
	}
	cur, ok := reg.Get("node-01")
	if !ok || cur.Generation != e2.Generation {
		t.Fatalf("expected e2 to remain active")
	}

	if list := reg.List("env", "prod"); len(list) != 1 {
		t.Fatalf("expected 1 matching target, got %d", len(list))
	}
	if list := reg.List("env", "staging"); len(list) != 0 {
		t.Fatalf("expected 0 matching targets, got %d", len(list))
	}

	if !reg.Unregister("node-01", e2.Generation) {
		t.Fatal("active unregister must return true")
	}
	if _, ok := reg.Get("node-01"); ok {
		t.Fatal("expected node-01 to be removed")
	}
}
