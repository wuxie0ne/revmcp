// Package channel manages persisted channel state and signed credentials.
package channel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/revmcp/revmcp/proto"
)

const (
	Agent = "agent"
	MCP   = "mcp"
)

var (
	ErrInvalid  = errors.New("invalid channel or credential")
	ErrDenied   = errors.New("invalid or inactive credential")
	ErrNotFound = errors.New("channel not found")
	ErrExists   = errors.New("channel name already exists")
)

// Policy is resolved at issuance and remains attached to the channel.
type Policy struct {
	Target    string        `json:"target_rule"`
	Mode      proto.Mode    `json:"agent_mode"`
	AgentTTL  time.Duration `json:"agent_ttl"`
	MCPScopes []string      `json:"mcp_scopes"`
	MCPTTL    time.Duration `json:"mcp_ttl"`
}

type credential struct {
	Version string `json:"version"`
	KeyID   string `json:"key_id"`
	Expires int64  `json:"expires"`
	Revoked bool   `json:"revoked,omitempty"`
}

// Record is the persisted channel and its current credential versions.
type Record struct {
	admission *sync.Mutex
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Policy    Policy     `json:"policy"`
	Agent     credential `json:"agent"`
	MCP       credential `json:"mcp"`
}

// Detail contains administrator-facing metadata and explicitly requested tokens.
type Detail struct {
	ChannelID    string     `json:"-"`
	Name         string     `json:"channel"`
	Target       string     `json:"target_rule"`
	Mode         proto.Mode `json:"access"`
	AgentExpires time.Time  `json:"agent_expires_at"`
	MCPExpires   time.Time  `json:"mcp_expires_at"`
	AgentActive  bool       `json:"agent_active"`
	MCPActive    bool       `json:"mcp_active"`
	MCPScopes    []string   `json:"mcp_scopes"`
	Targets      []string   `json:"connected_targets,omitempty"`
	Enrollment   string     `json:"enrollment_token,omitempty"`
	Bearer       string     `json:"mcp_bearer,omitempty"`
}

type claims struct {
	Kind    string     `json:"kind"`
	ID      string     `json:"channel_id"`
	Version string     `json:"ver"`
	Expires int64      `json:"exp"`
	Target  string     `json:"target_rule"`
	Mode    proto.Mode `json:"mode,omitempty"`
	Scopes  []string   `json:"scopes,omitempty"`
}

type state struct {
	KeyIDs  map[string]string `json:"signing_key_ids,omitempty"`
	Version int               `json:"version"`
	Records map[string]Record `json:"channels"`
}

// Store owns one local state file. Its process lock excludes a second Hub
// using the same path, and updates replace the entire file atomically.
type Store struct {
	path   string
	lock   *os.File
	keys   map[string][]byte
	keyIDs map[string]string
	now    func() time.Time
	mu     sync.RWMutex
	data   state
	byID   map[string]string
}

func Open(statePath, agentSecret, mcpSecret string, acceptKeyChange bool) (*Store, error) {
	if statePath == "" || len(strings.TrimSpace(agentSecret)) < 16 ||
		len(strings.TrimSpace(mcpSecret)) < 16 || agentSecret == mcpSecret {
		return nil, errors.New("channels require a state path and distinct signing secrets of at least 16 bytes")
	}
	lock, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open channel state lock: ensure directory %q exists and is writable: %w", filepath.Dir(statePath), err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock channel state: %w", err)
	}
	store := &Store{
		path: statePath, lock: lock, now: time.Now,
		keys: map[string][]byte{Agent: []byte(agentSecret), MCP: []byte(mcpSecret)},
		data: state{Version: 1, Records: make(map[string]Record)},
		byID: make(map[string]string),
	}
	store.keyIDs = make(map[string]string, len(store.keys))
	for kind, key := range store.keys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte("revmcp signing key identifier v1"))
		store.keyIDs[kind] = hex.EncodeToString(mac.Sum(nil)[:16])
	}
	if err := store.load(acceptKeyChange); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.lock.Close() }

func (s *Store) load(acceptKeyChange bool) error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s.commit(s.data.Records)
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		return fmt.Errorf("decode channel state: %w", err)
	}
	if s.data.Version != 1 || s.data.Records == nil {
		return errors.New("unsupported channel state format")
	}
	for name, record := range s.data.Records {
		if name != record.Name || !ValidName(name) || !validID(record.ID) ||
			!validID(record.Agent.Version) || !validID(record.MCP.Version) ||
			!validID(record.Agent.KeyID) || !validID(record.MCP.KeyID) ||
			record.Agent.Expires <= 0 || record.MCP.Expires <= 0 || record.Policy.Validate() != nil ||
			s.byID[record.ID] != "" {
			return errors.New("invalid record in channel state")
		}
		record.admission = new(sync.Mutex)
		s.data.Records[name] = record
		s.byID[record.ID] = name
	}
	return s.reconcileSigningKeys(acceptKeyChange)
}

// Old state files did not record the current keys separately. Their active
// credential metadata still identifies which keys were in use.
func (s *Store) reconcileSigningKeys(accept bool) error {
	if s.data.KeyIDs != nil && (!validID(s.data.KeyIDs[Agent]) || !validID(s.data.KeyIDs[MCP])) {
		return errors.New("invalid signing key identifiers in channel state")
	}
	next := s.recordsCopy()
	update := s.data.KeyIDs == nil
	for _, kind := range []string{Agent, MCP} {
		saved := s.data.KeyIDs[kind]
		if saved != "" && saved != s.keyIDs[kind] {
			if !accept {
				return signingKeyChangeError(kind)
			}
			update = true
		}
		for name, record := range next {
			value, _ := record.credential(kind)
			if value.KeyID == s.keyIDs[kind] || value.Revoked {
				continue
			}
			if !accept {
				return signingKeyChangeError(kind)
			}
			value.Revoked = true
			record.setCredential(kind, value)
			next[name] = record
			update = true
		}
	}
	if update {
		return s.commit(next)
	}
	return nil
}

func signingKeyChangeError(kind string) error {
	return fmt.Errorf("%s channel signing key changed: restore the configured key or restart with --accept-signing-key-change to revoke affected credentials", kind)
}

func (s *Store) recordsCopy() map[string]Record {
	out := make(map[string]Record, len(s.data.Records))
	for name, record := range s.data.Records {
		out[name] = record
	}
	return out
}

func (s *Store) commit(records map[string]Record) error {
	dir := filepath.Dir(s.path)
	file, err := os.CreateTemp(dir, ".revmcp-state-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	if err := json.NewEncoder(file).Encode(state{Version: 1, Records: records, KeyIDs: s.keyIDs}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := os.Rename(file.Name(), s.path); err != nil {
		return err
	}
	// After rename the new state is authoritative, including if directory sync fails.
	s.data.Records = records
	s.data.KeyIDs = s.keyIDs
	return directory.Sync()
}

func ValidName(name string) bool {
	if len(name) == 0 || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", c) {
			return false
		}
	}
	return true
}

func (p Policy) Validate() error {
	if p.Target == "" || p.Target == "." || p.Target == ".." || len(p.Target) > 128 || strings.ContainsAny(p.Target, "/\\ \t\r\n") {
		return fmt.Errorf("%w: invalid target rule", ErrInvalid)
	}
	if _, err := path.Match(p.Target, ""); err != nil {
		return fmt.Errorf("%w: invalid target rule", ErrInvalid)
	}
	for _, c := range p.Target {
		if !strings.ContainsRune("*?[]^", c) && c != '.' && !ValidName(string(c)) {
			return fmt.Errorf("%w: invalid target rule", ErrInvalid)
		}
	}
	if _, err := proto.ParseMode(string(p.Mode)); err != nil || p.AgentTTL < time.Second || p.MCPTTL < time.Second {
		return fmt.Errorf("%w: invalid Agent mode or credential duration", ErrInvalid)
	}
	if len(p.MCPScopes) == 0 {
		return fmt.Errorf("%w: at least one MCP scope is required", ErrInvalid)
	}
	for _, scope := range p.MCPScopes {
		switch scope {
		case "read", "exec:restricted", "exec:full", "exec:session", "file:upload":
		default:
			return fmt.Errorf("%w: unsupported MCP scope", ErrInvalid)
		}
	}
	return nil
}

func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16
}

func randomID() string {
	var data [16]byte
	_, _ = rand.Read(data[:]) // Go 1.25 guarantees success or terminates.
	return hex.EncodeToString(data[:])
}

func (r Record) credential(kind string) (credential, error) {
	switch kind {
	case Agent:
		return r.Agent, nil
	case MCP:
		return r.MCP, nil
	default:
		return credential{}, fmt.Errorf("%w: kind must be agent or mcp", ErrInvalid)
	}
}

func (r *Record) setCredential(kind string, value credential) {
	if kind == Agent {
		r.Agent = value
	} else {
		r.MCP = value
	}
}

func (s *Store) newCredential(kind string, ttl time.Duration) credential {
	return credential{Version: randomID(), KeyID: s.keyIDs[kind], Expires: s.now().Add(ttl).Unix()}
}

func (s *Store) Issue(name string, policy Policy) (Detail, error) {
	if !ValidName(name) {
		return Detail{}, fmt.Errorf("%w: invalid channel name", ErrInvalid)
	}
	if err := policy.Validate(); err != nil {
		return Detail{}, err
	}
	policy.MCPScopes = slices.Clone(policy.MCPScopes)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data.Records[name]; exists {
		return Detail{ChannelID: s.data.Records[name].ID}, ErrExists
	}
	record := Record{ID: randomID(), Name: name, Policy: policy, admission: new(sync.Mutex),
		Agent: s.newCredential(Agent, policy.AgentTTL), MCP: s.newCredential(MCP, policy.MCPTTL)}
	next := s.recordsCopy()
	next[name] = record
	err := s.commit(next)
	if s.data.Records[name].ID == record.ID {
		s.byID[record.ID] = name
	}
	if err != nil {
		return Detail{ChannelID: record.ID}, err
	}
	return s.detail(record, true, ""), nil
}

func (s *Store) Change(name, kind string, rotate bool) (Detail, error) {
	previous, ok := s.lookup(name)
	if !ok {
		return Detail{}, ErrNotFound
	}
	if kind == Agent {
		previous.admission.Lock()
		defer previous.admission.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.data.Records[name]
	if !exists || record.ID != previous.ID {
		return Detail{}, ErrNotFound
	}
	value, err := record.credential(kind)
	if err != nil {
		return Detail{ChannelID: record.ID}, err
	}
	if rotate {
		ttl := record.Policy.MCPTTL
		if kind == Agent {
			ttl = record.Policy.AgentTTL
		}
		value = s.newCredential(kind, ttl)
	} else {
		value.Revoked = true
	}
	record.setCredential(kind, value)
	next := s.recordsCopy()
	next[name] = record
	if err := s.commit(next); err != nil {
		return Detail{ChannelID: record.ID}, err
	}
	return s.detail(record, rotate, kind), nil
}

// Delete coordinates durable invalidation with removal of that channel's connections.
func (s *Store) Delete(name string, detach func(id string)) (string, error) {
	previous, ok := s.lookup(name)
	if !ok {
		return "", ErrNotFound
	}
	previous.admission.Lock()
	defer previous.admission.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.data.Records[name]
	if !exists || record.ID != previous.ID {
		return "", ErrNotFound
	}
	next := s.recordsCopy()
	delete(next, name)
	err := s.commit(next)
	if _, stillExists := s.data.Records[name]; !stillExists {
		delete(s.byID, record.ID)
		detach(record.ID)
	}
	return record.ID, err
}

func (s *Store) ID(name string) (string, bool) {
	record, ok := s.lookup(name)
	return record.ID, ok
}

func (s *Store) lookup(name string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.data.Records[name]
	return record, ok
}

func (s *Store) List(name string, reveal bool, connected func(string) []string) ([]Detail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.data.Records[name]; name != "" && !exists {
		return nil, ErrNotFound
	}
	items := make([]Detail, 0)
	for _, record := range s.data.Records {
		if name == "" || record.Name == name {
			info := s.detail(record, reveal, "")
			info.Targets = connected(record.ID)
			items = append(items, info)
		}
	}
	slices.SortFunc(items, func(a, b Detail) int { return strings.Compare(a.Name, b.Name) })
	return items, nil
}

func (s *Store) detail(record Record, reveal bool, kind string) Detail {
	now := s.now().Unix()
	info := Detail{
		ChannelID: record.ID, Name: record.Name, Target: record.Policy.Target, Mode: record.Policy.Mode,
		AgentExpires: time.Unix(record.Agent.Expires, 0), MCPExpires: time.Unix(record.MCP.Expires, 0),
		AgentActive: s.active(Agent, record.Agent, now),
		MCPActive:   s.active(MCP, record.MCP, now),
		MCPScopes:   slices.Clone(record.Policy.MCPScopes),
	}
	if reveal && info.AgentActive && (kind == "" || kind == Agent) {
		info.Enrollment = s.sign(record, Agent, record.Agent)
	}
	if reveal && info.MCPActive && (kind == "" || kind == MCP) {
		info.Bearer = s.sign(record, MCP, record.MCP)
	}
	return info
}

func (s *Store) active(kind string, value credential, now int64) bool {
	return !value.Revoked && value.Expires > now && value.KeyID == s.keyIDs[kind]
}

func prefix(kind string) string { return "revmcp-" + kind + "-v1." }

func (s *Store) sign(record Record, kind string, value credential) string {
	payload := claims{Kind: kind, ID: record.ID, Version: value.Version, Expires: value.Expires, Target: record.Policy.Target}
	if kind == Agent {
		payload.Mode = record.Policy.Mode
	} else {
		payload.Scopes = record.Policy.MCPScopes
	}
	raw, _ := json.Marshal(payload)
	body := prefix(kind) + base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.keys[kind])
	_, _ = mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks the current signed value. Verification never holds a lock
// across a network call.
func (s *Store) Verify(token, kind string) (Record, time.Time, error) {
	if len(token) > 8192 || !strings.HasPrefix(token, prefix(kind)) {
		return Record{}, time.Time{}, ErrDenied
	}
	body, _, ok := strings.Cut(strings.TrimPrefix(token, prefix(kind)), ".")
	if !ok {
		return Record{}, time.Time{}, ErrDenied
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Record{}, time.Time{}, ErrDenied
	}
	var payload claims
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Kind != kind {
		return Record{}, time.Time{}, ErrDenied
	}
	return s.verifyRecord(token, kind, payload.ID)
}

func (s *Store) verifyRecord(token, kind, id string) (Record, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, exists := s.data.Records[s.byID[id]]
	if !exists {
		return Record{}, time.Time{}, ErrDenied
	}
	value, err := record.credential(kind)
	if err != nil || !s.active(kind, value, s.now().Unix()) ||
		!hmac.Equal([]byte(token), []byte(s.sign(record, kind, value))) {
		return Record{}, time.Time{}, ErrDenied
	}
	return record, time.Unix(value.Expires, 0), nil
}

// AdmitAgent serializes activation with changes to this channel's Agent
// credential and channel deletion. Other channels remain available.
func (s *Store) AdmitAgent(token string, use func(Record) error) (string, error) {
	record, _, err := s.Verify(token, Agent)
	if err != nil {
		return "", err
	}
	record.admission.Lock()
	defer record.admission.Unlock()
	current, _, err := s.verifyRecord(token, Agent, record.ID)
	if err != nil {
		return record.ID, err
	}
	return record.ID, use(current)
}
