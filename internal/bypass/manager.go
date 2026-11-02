package bypass

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager holds the live passthrough list, assembled from three sources:
//
//   - built-in defaults (Defaults()), which cannot be removed;
//   - user patterns from config (BypassDomains);
//   - patterns added at runtime, persisted to bypass.txt in the data dir.
//
// It is safe for concurrent use: the proxy calls Match on every CONNECT while
// the dashboard/CLI may be editing the list.
type Manager struct {
	file     string
	defaults []string
	user     []string

	mu      sync.RWMutex
	added   []string
	matcher *Matcher
	log     *slog.Logger
}

// NewManager builds a Manager. userPatterns come from config; the runtime
// additions file (bypass.txt) is loaded from dataDir if present.
func NewManager(dataDir string, userPatterns []string, log *slog.Logger) (*Manager, error) {
	m := &Manager{
		file:     filepath.Join(dataDir, "bypass.txt"),
		defaults: Defaults(),
		user:     dedupe(userPatterns),
		log:      log,
	}
	m.added = m.loadFile()
	m.rebuild()
	return m, nil
}

// Match reports whether host should bypass interception.
func (m *Manager) Match(host string) bool {
	m.mu.RLock()
	matcher := m.matcher
	m.mu.RUnlock()
	return matcher.Match(host)
}

// Add adds a runtime pattern and persists it. Adding something already
// covered (by any source) is a no-op.
func (m *Manager) Add(pattern string) error {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.all() {
		if p == pattern {
			return nil
		}
	}
	m.added = append(m.added, pattern)
	m.rebuildLocked()
	return m.persistLocked()
}

// Remove deletes a runtime-added pattern (defaults and config entries cannot
// be removed here). Returns false if the pattern was not a runtime addition.
func (m *Manager) Remove(pattern string) (bool, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.added[:0]
	found := false
	for _, p := range m.added {
		if p == pattern {
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		return false, nil
	}
	m.added = append([]string(nil), out...)
	m.rebuildLocked()
	return true, m.persistLocked()
}

// Lists returns the three source lists (copies), for display.
func (m *Manager) Lists() (defaults, user, added []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.defaults...),
		append([]string(nil), m.user...),
		append([]string(nil), m.added...)
}

func (m *Manager) all() []string {
	all := make([]string, 0, len(m.defaults)+len(m.user)+len(m.added))
	all = append(all, m.defaults...)
	all = append(all, m.user...)
	all = append(all, m.added...)
	return all
}

func (m *Manager) rebuild() {
	m.mu.Lock()
	m.rebuildLocked()
	m.mu.Unlock()
}

func (m *Manager) rebuildLocked() { m.matcher = New(m.all()) }

func (m *Manager) loadFile() []string {
	f, err := os.Open(m.file)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return dedupe(out)
}

func (m *Manager) persistLocked() error {
	var b strings.Builder
	b.WriteString("# Adnesia runtime passthrough list — hosts NOT intercepted.\n")
	b.WriteString("# One pattern per line; '*.' matches a domain and its subdomains.\n")
	b.WriteString("# Written " + time.Now().Format(time.RFC3339) + "\n\n")
	sorted := append([]string(nil), m.added...)
	sort.Strings(sorted)
	for _, p := range sorted {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return os.WriteFile(m.file, []byte(b.String()), 0o644)
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
