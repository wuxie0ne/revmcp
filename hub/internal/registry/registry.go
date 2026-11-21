package registry

import (
	"context"
	"sort"
	"sync"
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
	ChannelID           string
	Info                proto.AgentInfo
	Caller              Caller
	ConnectedAt         time.Time
	EnrollmentExpiresAt time.Time
	Generation          uint64
	pending             bool
}

type key struct {
	channelID string
	targetID  string
}

// Registry indexes online Agents by channel and target.
type Registry struct {
	mu      sync.RWMutex
	entries map[key]*Entry
	gen     uint64
}

func New() *Registry {
	return &Registry{entries: make(map[key]*Entry)}
}

// Reserve refuses a second connection for a managed target, including one still registering.
func (r *Registry) Reserve(channelID string, info proto.AgentInfo, caller Caller, enrollmentExpiresAt time.Time) (*Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key{channelID, info.TargetID}
	if _, exists := r.entries[k]; exists {
		return nil, false
	}
	r.gen++
	entry := &Entry{
		ChannelID: channelID, Info: info, Caller: caller, Generation: r.gen,
		ConnectedAt: time.Now().UTC(), EnrollmentExpiresAt: enrollmentExpiresAt, pending: true,
	}
	r.entries[k] = entry
	return entry, true
}

func (r *Registry) Activate(channelID, targetID string, generation uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.entries[key{channelID, targetID}]; entry != nil && entry.Generation == generation {
		entry.pending = false
	}
}

func (r *Registry) UnregisterIn(channelID, targetID string, generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key{channelID, targetID}
	cur, ok := r.entries[k]
	if !ok || cur.Generation != generation {
		return false
	}
	delete(r.entries, k)
	return true
}

func (r *Registry) GetIn(channelID, targetID string) (*Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[key{channelID, targetID}]
	if !ok || entry.pending {
		return nil, false
	}
	return entry, true
}

func (r *Registry) ListIn(channelID, tagKey, tagVal string) []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Entry, 0)
	for k, entry := range r.entries {
		if k.channelID != channelID || entry.pending {
			continue
		}
		if tagKey != "" {
			value, ok := entry.Info.Tags[tagKey]
			if !ok || tagVal != "" && value != tagVal {
				continue
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Info.TargetID < out[j].Info.TargetID
	})
	return out
}

// ExpiredEnrollments snapshots live connections admitted with credentials that have expired.
func (r *Registry) ExpiredEnrollments(now time.Time) []*Entry {
	r.mu.RLock()
	var entries []*Entry
	for _, entry := range r.entries {
		if !entry.pending && !entry.EnrollmentExpiresAt.After(now) {
			entries = append(entries, entry)
		}
	}
	r.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ChannelID != entries[j].ChannelID {
			return entries[i].ChannelID < entries[j].ChannelID
		}
		return entries[i].Info.TargetID < entries[j].Info.TargetID
	})
	return entries
}

func (r *Registry) Detach(channelID string) []Caller {
	r.mu.Lock()
	defer r.mu.Unlock()
	var callers []Caller
	for k, entry := range r.entries {
		if k.channelID == channelID {
			callers = append(callers, entry.Caller)
			delete(r.entries, k)
		}
	}
	return callers
}
