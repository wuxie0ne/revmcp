package registry

import (
	"context"
	"testing"
	"time"

	"github.com/revmcp/revmcp/proto"
)

type stubCaller struct{}

func (*stubCaller) Call(_ context.Context, _ string, _ any, _ any) error { return nil }
func (*stubCaller) Close() error                                         { return nil }

func TestRegistryReservationAndStaleUnregister(t *testing.T) {
	t.Parallel()

	reg := New()
	expires := time.Now().Add(time.Hour)
	info := proto.AgentInfo{TargetID: "node-01", Mode: proto.ModeReadOnly, Tags: map[string]string{"env": "prod"}}
	first, ok := reg.Reserve("channel-a", info, &stubCaller{}, expires)
	if !ok {
		t.Fatal("first reservation failed")
	}
	if _, ok := reg.GetIn("channel-a", info.TargetID); ok {
		t.Fatal("pending reservation was visible")
	}
	if _, ok := reg.Reserve("channel-a", info, &stubCaller{}, expires); ok {
		t.Fatal("accepted a duplicate reservation in the same channel")
	}
	if _, ok := reg.Reserve("channel-b", info, &stubCaller{}, expires); !ok {
		t.Fatal("refused the same target name in another channel")
	}

	reg.Detach("channel-a")
	next, ok := reg.Reserve("channel-a", info, &stubCaller{}, expires)
	if !ok {
		t.Fatal("reservation after detach failed")
	}
	reg.Activate("channel-a", info.TargetID, next.Generation)
	if reg.UnregisterIn("channel-a", info.TargetID, first.Generation) {
		t.Fatal("stale unregister removed the new target")
	}
	if list := reg.ListIn("channel-a", "env", "prod"); len(list) != 1 || list[0].Generation != next.Generation {
		t.Fatalf("expected one matching active target, got %v", list)
	}
	if list := reg.ListIn("channel-a", "env", "staging"); len(list) != 0 {
		t.Fatalf("expected no matching targets, got %d", len(list))
	}
	if !reg.UnregisterIn("channel-a", info.TargetID, next.Generation) {
		t.Fatal("active unregister failed")
	}
}
