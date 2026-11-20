package policy

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastTick time.Time
}

// RateLimiter enforces a per-key token bucket rate limit.
// A nil RateLimiter or one with rps <= 0 permits all requests.
type RateLimiter struct {
	mu      sync.Mutex
	rps     float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

// NewRateLimiter constructs a token-bucket RateLimiter. When rps <= 0, returns nil (disabled).
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = max(1, int(rps*2))
	}
	return &RateLimiter{
		rps:     rps,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow consumes one token for key and reports whether the call is allowed.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil || r.rps <= 0 {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	b, ok := r.buckets[key]
	if !ok {
		r.buckets[key] = &bucket{
			tokens:   r.burst - 1,
			lastTick: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastTick).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.rps
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.lastTick = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
