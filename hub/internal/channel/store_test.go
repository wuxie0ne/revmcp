package channel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/revmcp/revmcp/proto"
)

const (
	testAgentKey = "test-agent-signing-key"
	testMCPKey   = "test-mcp-signing-key"
)

func TestPersistentCredentialLifecycle(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "channel-state.json")
	store, err := Open(statePath, testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Target: "node-*", Mode: proto.ModeReadOnly, AgentTTL: time.Hour, MCPTTL: 2 * time.Hour, MCPScopes: []string{"read"}}
	issued, err := store.Issue("work", policy)
	if err != nil {
		t.Fatal(err)
	}
	stateFile, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateFile), issued.Enrollment) || strings.Contains(string(stateFile), issued.Bearer) {
		t.Fatal("bearer values were persisted")
	}
	check := func(value string, kind string, success bool) {
		t.Helper()
		_, _, err := store.Verify(value, kind)
		if (err == nil) != success {
			t.Fatalf("kind %s, want valid %v, got %v", kind, success, err)
		}
	}
	check(issued.Enrollment, Agent, true)
	check(issued.Bearer, MCP, true)
	check(issued.Bearer, Agent, false)
	check(issued.Enrollment, MCP, false)
	if second, err := Open(statePath, testAgentKey, testMCPKey, false); err == nil {
		_ = second.Close()
		t.Fatal("second writer opened the same state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(statePath, testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	connected := func(string) []string { return []string{"node-1"} }
	list, err := store.List("work", false, connected)
	if err != nil || len(list) != 1 || list[0].Enrollment != "" || list[0].Bearer != "" {
		t.Fatal("metadata listing exposed credential values")
	}
	list, err = store.List("work", true, connected)
	if err != nil || len(list) != 1 || list[0].Enrollment != issued.Enrollment || list[0].Bearer != issued.Bearer {
		t.Fatal("reveal did not return the original values after reopening state")
	}
	rotated, err := store.Change("work", MCP, true)
	if err != nil || rotated.Bearer == "" || rotated.Bearer == issued.Bearer || rotated.Enrollment != "" {
		t.Fatal("rotation did not return only a fresh MCP Bearer")
	}
	check(issued.Bearer, MCP, false)
	check(rotated.Bearer, MCP, true)
	check(issued.Enrollment, Agent, true)
	if _, err := store.Change("work", Agent, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(statePath, testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	check(issued.Enrollment, Agent, false)
	list, err = store.List("work", true, connected)
	if err != nil || len(list) != 1 || list[0].Enrollment != "" || list[0].Bearer != rotated.Bearer {
		t.Fatal("a revoked credential was revealed after restart")
	}
	oldID, _ := store.ID("work")
	if _, err := store.Delete("work", func(id string) {
		if id != oldID {
			t.Error("delete detached a different channel")
		}
	}); err != nil {
		t.Fatal(err)
	}
	recreated, err := store.Issue("work", policy)
	if err != nil {
		t.Fatal(err)
	}
	newID, _ := store.ID("work")
	if oldID == newID {
		t.Fatal("recreated channel reused its predecessor's identity")
	}
	check(rotated.Bearer, MCP, false)
	check(recreated.Bearer, MCP, true)
	store.now = func() time.Time { return recreated.MCPExpires.Add(time.Second) }
	check(recreated.Bearer, MCP, false)
	list, err = store.List("work", true, connected)
	if err != nil || list[0].Bearer != "" || len(list[0].Targets) != 1 {
		t.Fatal("expiry must hide values without hiding connected targets")
	}
}

func TestConcurrentIssueSameName(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "channels.json"), testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	policy := Policy{Target: "one", Mode: proto.ModeReadOnly, MCPScopes: []string{"read"}, AgentTTL: time.Hour, MCPTTL: time.Hour}
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range cap(results) {
		group.Go(func() {
			_, err := store.Issue("one", policy)
			results <- err
		})
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrExists):
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful creations", successes)
	}
}

func TestDeleteCoordinatesWithAdmission(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "channels.json"), testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	policy := Policy{Target: "one", Mode: proto.ModeReadOnly, MCPScopes: []string{"read"}, AgentTTL: time.Hour, MCPTTL: time.Hour}
	issued, err := store.Issue("one", policy)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	finish := make(chan struct{})
	registered := make(chan struct{})
	admission := make(chan error, 1)
	go func() {
		_, err := store.AdmitAgent(issued.Enrollment, func(Record) error {
			close(started)
			<-finish
			close(registered)
			return nil
		})
		admission <- err
	}()
	select {
	case err := <-admission:
		t.Fatalf("admission failed before callback: %v", err)
	case <-started:
	}
	deleted := make(chan error, 1)
	go func() {
		_, err := store.Delete("one", func(string) {
			select {
			case <-registered:
			default:
				t.Error("channel deletion raced past registration")
			}
		})
		deleted <- err
	}()
	other := make(chan error, 1)
	go func() {
		_, err := store.Issue("other", policy)
		other <- err
	}()
	select {
	case err := <-other:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Error("an admission reply blocked updates to another channel")
	}
	close(finish)
	if err := <-admission; err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Verify(issued.Enrollment, Agent); !errors.Is(err, ErrDenied) {
		t.Fatalf("expected deleted credential to be rejected, got %v", err)
	}
}

func TestSigningKeyChangeCannotReviveCredential(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "channels.json")
	const replacementKey = "different-test-mcp-signing-key"
	open := func(key string, accept bool) *Store {
		t.Helper()
		store, err := Open(statePath, testAgentKey, key, accept)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	store := open(testMCPKey, false)
	policy := Policy{Target: "one", Mode: proto.ModeReadOnly, MCPScopes: []string{"read"}, AgentTTL: time.Hour, MCPTTL: time.Hour}
	first, err := store.Issue("one", policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if refused, err := Open(statePath, testAgentKey, replacementKey, false); err == nil {
		_ = refused.Close()
		t.Fatal("unexpected key change was accepted")
	}
	store = open(replacementKey, true)
	credentials, err := store.List("one", true, func(string) []string { return nil })
	if err != nil || len(credentials) != 1 || credentials[0].Bearer != "" || credentials[0].Enrollment != first.Enrollment {
		t.Fatal("key change revealed an affected credential or changed the unaffected enrollment token")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = open(testMCPKey, true)
	if _, _, err := store.Verify(first.Bearer, MCP); !errors.Is(err, ErrDenied) {
		t.Fatalf("restoring the old key revived a revoked credential: %v", err)
	}
	next, err := store.Change("one", MCP, true)
	if err != nil || next.Bearer == "" || next.Bearer == first.Bearer {
		t.Fatal("new credential was not generated after an approved key change")
	}
}

func TestRetiredUploadScopeInStoredChannels(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "channel-state.json")
	store, err := Open(statePath, testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	original := Policy{
		Target: "node", Mode: proto.ModeFull, AgentTTL: time.Hour, MCPTTL: time.Hour,
		MCPScopes: []string{"read"},
	}
	if _, err := store.Issue("work", original); err != nil {
		t.Fatal(err)
	}

	// Write the policy in the shape persisted by v0.2.0.
	records := store.recordsCopy()
	old := records["work"]
	old.Policy.MCPScopes = []string{"read", "file:upload"}
	records["work"] = old
	if err := store.commit(records); err != nil {
		t.Fatal(err)
	}
	oldBearer := store.detail(old, true, "").Bearer
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(statePath, testAgentKey, testMCPKey, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	record, _, err := store.Verify(oldBearer, MCP)
	if err != nil || strings.Join(record.Policy.MCPScopes, ",") != "read,file:upload" {
		t.Fatalf("existing credential changed during upgrade: %v", err)
	}
	if _, err := store.Issue("new", old.Policy); !errors.Is(err, ErrInvalid) {
		t.Fatalf("new channel accepted retired scope: %v", err)
	}
}
