// Package config loads and persists Adnesia's settings.
//
// Settings live in a single JSON file under the user's config directory
// (on Windows that is %AppData%\Adnesia\config.json). The same directory
// holds the generated root CA and, later, cached filter lists.
package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
)

// FilterList is one downloadable block list and the feature category whose
// toggle governs its rules.
type FilterList struct {
	URL      string `json:"url"`
	Category string `json:"category"` // ads | privacy | annoyances | security
	Name     string `json:"name"`
}

// Config is the on-disk settings for Adnesia.
type Config struct {
	// ProxyAddr is the address the local MITM proxy listens on and that the
	// Windows system proxy is pointed at.
	ProxyAddr string `json:"proxy_addr"`

	// DashboardAddr is the address the local web dashboard listens on. It must
	// be a loopback address so it is reachable directly (localhost bypasses
	// the system proxy) and never exposed to the network.
	DashboardAddr string `json:"dashboard_addr"`

	// TransparentPort is the local port the experimental WinDivert transparent
	// capture redirects to (Phase 7, off unless -transparent is passed).
	TransparentPort int `json:"transparent_port"`

	// Enabled records whether filtering should be on. Phase 1 only toggles
	// the proxy/system-proxy; later phases consult this for the kill switch.
	Enabled bool `json:"enabled"`

	// BypassDomains are hosts that must NOT be MITM'd (certificate pinning,
	// banking apps, etc.). They are tunneled straight through. Expanded into
	// a real manager in Phase 5; a small safe default seeds it here.
	BypassDomains []string `json:"bypass_domains"`

	// Lists are the block lists to download, each tagged with the feature
	// category it belongs to ("ads", "privacy", "annoyances", "security").
	Lists []FilterList `json:"lists"`

	// FilterLists is the deprecated plain-URL form, kept so old config files
	// still load; it is no longer used.
	FilterLists []string `json:"filter_lists,omitempty"`

	// Feature toggles, mirrored by the dashboard switches.
	AdBlocking    bool `json:"ad_blocking"`
	Privacy       bool `json:"privacy_protection"`
	WebProtection bool `json:"web_protection"`
	Annoyances    bool `json:"annoyances_blocking"`
	GhostMode     bool `json:"ghost_mode"`

	// Transparent enables the experimental WinDivert system-wide capture at
	// startup (needs admin + WinDivert). Also toggleable from the dashboard.
	Transparent bool `json:"transparent"`

	// CosmeticGeneric controls whether site-agnostic ("generic") cosmetic
	// selectors are injected into every page. These are numerous and add
	// page weight, so they default off; domain-specific cosmetic rules are
	// always applied and catch most real site ad containers.
	CosmeticGeneric bool `json:"cosmetic_generic"`

	// dir is the resolved data directory. Not serialized.
	dir string `json:"-"`
}

// Default returns a Config with sensible starting values.
func Default() *Config {
	return &Config{
		ProxyAddr:       "127.0.0.1:8080",
		DashboardAddr:   "127.0.0.1:8081",
		TransparentPort: 8082,
		Enabled:         true,
		AdBlocking:      true,
		Privacy:         true,
		WebProtection:   true,
		Annoyances:      true,
		GhostMode:       false,
		// Curated passthrough defaults live in the bypass package; this is for
		// the user's own additions (e.g. "*.mybank.com", "*.corp.internal").
		BypassDomains: []string{},
		Lists: []FilterList{
			{"https://easylist.to/easylist/easylist.txt", "ads", "EasyList"},
			{"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "ads", "Peter Lowe's List"},
			{"https://filters.adtidy.org/extension/ublock/filters/2.txt", "ads", "AdGuard Base"},
			{"https://easylist.to/easylist/easyprivacy.txt", "privacy", "EasyPrivacy"},
			{"https://filters.adtidy.org/extension/ublock/filters/14.txt", "annoyances", "AdGuard Annoyances"},
			{"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt", "security", "URLhaus Malware"},
		},
	}
}

// Dir returns Adnesia's data directory, creating it if necessary.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "Adnesia")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// path returns the config file path inside dir.
func path(dir string) string {
	return filepath.Join(dir, "config.json")
}

// Load reads the config from disk, falling back to defaults (and writing
// them out) when no config file exists yet.
func Load() (*Config, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		c := Default()
		c.dir = dir
		return c, c.Save()
	}
	if err != nil {
		return nil, err
	}

	c := Default() // defaults fill any fields missing from the file
	// Tolerate a UTF-8 BOM: editors (and PowerShell) often add one, and the
	// JSON parser would otherwise reject the whole file.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	c.dir = dir
	return c, nil
}

// Save writes the config back to disk.
func (c *Config) Save() error {
	if c.dir == "" {
		dir, err := Dir()
		if err != nil {
			return err
		}
		c.dir = dir
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path(c.dir), data, 0o644)
}

// DataDir returns the resolved data directory for this config.
func (c *Config) DataDir() string { return c.dir }
