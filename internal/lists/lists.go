// Package lists downloads filter lists, caches them on disk, and loads them
// into a filter.Engine.
//
// Downloads go direct (not through Adnesia's own proxy). A cached copy is
// reused while it is younger than maxAge; if a refresh fails but a cached copy
// exists, the stale copy is used so a network hiccup never leaves the user
// unprotected. The Phase 6 scheduler will call Refresh periodically.
package lists

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"adnesia/internal/config"
	"adnesia/internal/cosmetic"
	"adnesia/internal/filter"
)

// Manager downloads and caches the configured filter lists.
type Manager struct {
	dir    string // cache directory (created if missing)
	lists  []config.FilterList
	maxAge time.Duration
	client *http.Client
	log    *slog.Logger
}

// New returns a Manager caching lists under dir/lists.
func New(dataDir string, lists []config.FilterList, maxAge time.Duration, log *slog.Logger) (*Manager, error) {
	dir := filepath.Join(dataDir, "lists")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Manager{
		dir:    dir,
		lists:  lists,
		maxAge: maxAge,
		client: &http.Client{Timeout: 60 * time.Second},
		log:    log,
	}, nil
}

// categoryOf maps a config category string to a filter.Category.
func categoryOf(s string) filter.Category {
	switch s {
	case "privacy":
		return filter.CatPrivacy
	case "annoyances":
		return filter.CatAnnoyances
	case "security":
		return filter.CatSecurity
	default:
		return filter.CatAds
	}
}

// cachePath returns the on-disk path a URL's cached copy lives at.
func (m *Manager) cachePath(url string) string {
	sum := sha1.Sum([]byte(url))
	return filepath.Join(m.dir, hex.EncodeToString(sum[:])+".txt")
}

// Build downloads/refreshes every configured list and returns a network
// filter.Engine and a cosmetic.Engine loaded from them. A list that cannot be
// fetched and has no cache is skipped with a warning rather than failing the
// whole build.
func (m *Manager) Build(ctx context.Context) (*filter.Engine, *cosmetic.Engine, error) {
	engine := filter.NewEngine()
	cosEngine := cosmetic.NewEngine()
	for _, list := range m.lists {
		data, err := m.fetch(ctx, list.URL)
		if err != nil {
			m.log.Warn("skipping filter list", "name", list.Name, "err", err)
			continue
		}
		n := engine.AddListCat(data, categoryOf(list.Category))
		c := cosEngine.AddList(data)
		m.log.Info("loaded filter list", "name", list.Name, "category", list.Category, "network_rules", n, "cosmetic_rules", c)
	}
	m.log.Info("engines ready", "network_rules", engine.Count(), "cosmetic_rules", cosEngine.Count())
	return engine, cosEngine, nil
}

// fetch returns a list's bytes, downloading when the cache is missing or
// stale and falling back to a stale cache on download failure.
func (m *Manager) fetch(ctx context.Context, url string) ([]byte, error) {
	path := m.cachePath(url)

	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < m.maxAge {
		if data, err := os.ReadFile(path); err == nil {
			return data, nil
		}
	}

	data, dlErr := m.download(ctx, url)
	if dlErr != nil {
		// Fall back to any cached copy, however old.
		if data, err := os.ReadFile(path); err == nil {
			m.log.Warn("download failed, using cached copy", "url", url, "err", dlErr)
			return data, nil
		}
		return nil, dlErr
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		m.log.Warn("could not cache filter list", "url", url, "err", err)
	}
	return data, nil
}

func (m *Manager) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Adnesia/0.1 (+https://local)")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
}
