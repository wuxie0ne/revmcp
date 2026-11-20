package registry

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/revmcp/revmcp/proto"
)

// Caller invokes southbound RPC methods on a connected Agent.
type Caller interface {
	Call(ctx context.Context, method string, params any, resultDst any) error
	Close() error
}

// Entry represents a live registered Agent in the Hub registry.
type Entry struct {
	Info        proto.AgentInfo
	Caller      Caller
	ConnectedAt time.Time
	Generation  uint64
}

// Registry maintains a concurrency-safe map of online Agents keyed by target_id.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	gen     atomic.Uint64
}

// New creates an empty Registry.
func New() *Registry {
	return &Registry{
		entries: make(map[string]*Entry),
	}
}

// Register adds or smoothly replaces an online agent for info.TargetID.
// If an older connection exists for the same TargetID, it is returned so the caller can close it.
func (r *Registry) Register(info proto.AgentInfo, caller Caller) (entry *Entry, replaced *Entry) {
	gen := r.gen.Add(1)
	entry = &Entry{
		Info:        info,
		Caller:      caller,
		ConnectedAt: time.Now().UTC(),
		Generation:  gen,
	}

	r.mu.Lock()
	replaced = r.entries[info.TargetID]
	r.entries[info.TargetID] = entry
	r.mu.Unlock()

	return entry, replaced
}

// Unregister removes targetID only if the stored entry matches generation, preventing
// a stale disconnected session from evicting a newer reconnect.
func (r *Registry) Unregister(targetID string, generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cur, ok := r.entries[targetID]
	if !ok || cur.Generation != generation {
		return false
	}
	delete(r.entries, targetID)
	return true
}

// Get returns the active Entry for targetID, if online.
func (r *Registry) Get(targetID string) (*Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.entries[targetID]
	return entry, ok
}

// List returns all currently online targets sorted by TargetID, optionally filtered by a tag key=value.
func (r *Registry) List(tagKey, tagVal string) []*Entry {
	r.mu.RLock()
	out := make([]*Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		if tagKey != "" {
			v, ok := entry.Info.Tags[tagKey]
			if !ok || (tagVal != "" && v != tagVal) {
				continue
			}
		}
		out = append(out, entry)
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return out[i].Info.TargetID < out[j].Info.TargetID
	})
	return out
}
