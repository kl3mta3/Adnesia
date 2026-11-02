// Package stats tracks what the proxy has seen and blocked, broken down by
// category so the dashboard can show ads / trackers / threats separately, plus
// a small ring buffer of the most recently blocked requests. Everything is
// safe for concurrent use by the proxy's request handlers.
package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"adnesia/internal/filter"
)

// Rough per-blocked-request estimates for the "saved" figures, in the spirit
// of other blockers' dashboards. These are deliberately approximate.
const (
	bytesPerBlock = 50 * 1024          // ~50 KB of ad/tracker payload avoided
	timePerBlock  = 50 * time.Millisecond
)

// Entry is one blocked request, newest-first in Recent.
type Entry struct {
	Time time.Time `json:"time"`
	Host string    `json:"host"`
	URL  string    `json:"url"`
}

// Snapshot is an immutable view of the counters and recent blocks.
type Snapshot struct {
	Total       uint64  `json:"total"`
	Blocked     uint64  `json:"blocked"`
	Ads         uint64  `json:"ads"`
	Trackers    uint64  `json:"trackers"`
	Annoyances  uint64  `json:"annoyances"`
	Threats     uint64  `json:"threats"`
	SavedMB     float64 `json:"saved_mb"`
	SavedMinutes int    `json:"saved_minutes"`
	Recent      []Entry `json:"recent"`
}

// Stats holds live counters and a ring buffer of recent blocks.
type Stats struct {
	total   atomic.Uint64
	blocked atomic.Uint64
	byCat   [8]atomic.Uint64 // indexed by filter.Category

	mu   sync.Mutex
	ring []Entry
	next int
	full bool
}

// New returns a Stats keeping up to ringSize recent blocked entries.
func New(ringSize int) *Stats {
	if ringSize <= 0 {
		ringSize = 200
	}
	return &Stats{ring: make([]Entry, ringSize)}
}

// RecordAllowed counts a request that was let through.
func (s *Stats) RecordAllowed() { s.total.Add(1) }

// RecordBlocked counts a blocked request (tagged with its category) and
// records it in the ring buffer.
func (s *Stats) RecordBlocked(cat filter.Category, host, url string) {
	s.total.Add(1)
	s.blocked.Add(1)
	if int(cat) < len(s.byCat) {
		s.byCat[cat].Add(1)
	}

	s.mu.Lock()
	s.ring[s.next] = Entry{Time: time.Now(), Host: host, URL: url}
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
	s.mu.Unlock()
}

// Snapshot returns the current totals and recent blocks, newest first.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	var recent []Entry
	count := s.next
	if s.full {
		count = len(s.ring)
	}
	for i := 0; i < count; i++ {
		idx := (s.next - 1 - i + len(s.ring)) % len(s.ring)
		recent = append(recent, s.ring[idx])
	}
	s.mu.Unlock()

	blocked := s.blocked.Load()
	return Snapshot{
		Total:        s.total.Load(),
		Blocked:      blocked,
		Ads:          s.byCat[filter.CatAds].Load(),
		Trackers:     s.byCat[filter.CatPrivacy].Load(),
		Annoyances:   s.byCat[filter.CatAnnoyances].Load(),
		Threats:      s.byCat[filter.CatSecurity].Load(),
		SavedMB:      float64(blocked*bytesPerBlock) / (1024 * 1024),
		SavedMinutes: int(time.Duration(blocked) * timePerBlock / time.Minute),
		Recent:       recent,
	}
}
