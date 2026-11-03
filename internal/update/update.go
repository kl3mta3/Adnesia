// Package update checks GitHub Releases for a newer Adnesia version. It only
// notifies: it never downloads or replaces the running binary.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"adnesia/internal/dialer"
)

// Status is the last known result, as shown on the dashboard.
type Status struct {
	Current     string    `json:"current"`                // running version, e.g. "0.9.0"
	Latest      string    `json:"latest,omitempty"`       // newest release tag seen, without "v"
	URL         string    `json:"url,omitempty"`          // release page
	Available   bool      `json:"available"`              // latest is newer than current
	LastChecked time.Time `json:"last_checked,omitempty"` // zero until the first check
	Error       string    `json:"error,omitempty"`        // last check failed (network, API...)
	Checking    bool      `json:"checking"`
}

// Checker polls one GitHub repository's latest release.
type Checker struct {
	current  string
	endpoint string // releases/latest API URL
	client   *http.Client
	log      *slog.Logger

	mu     sync.Mutex
	status Status
	stop   chan struct{}
	once   sync.Once
}

// New returns a checker for github.com/<owner>/<repo> comparing against the
// running version. apiBase is overridable for tests ("" = api.github.com).
func New(owner, repo, current, apiBase string, log *slog.Logger) *Checker {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	if log == nil {
		log = slog.Default()
	}
	cur := strings.TrimPrefix(current, "v")
	return &Checker{
		current:  cur,
		endpoint: fmt.Sprintf("%s/repos/%s/%s/releases/latest", strings.TrimRight(apiBase, "/"), owner, repo),
		client: &http.Client{
			Timeout: 20 * time.Second,
			// Go straight out: never through our own proxy (loop), and from the
			// reserved port range so Kernel Mode leaves these packets alone.
			Transport: &http.Transport{
				Proxy:               nil,
				DialContext:         dialer.DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		log:    log,
		status: Status{Current: cur},
		stop:   make(chan struct{}),
	}
}

// Status returns the last result.
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Check queries GitHub now and returns the new status. A failed check keeps
// the last good result and records the error beside it.
func (c *Checker) Check(ctx context.Context) Status {
	c.mu.Lock()
	if c.status.Checking {
		s := c.status
		c.mu.Unlock()
		return s
	}
	c.status.Checking = true
	c.mu.Unlock()

	latest, url, err := c.fetchLatest(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Checking = false
	c.status.LastChecked = time.Now()
	if err != nil {
		c.status.Error = err.Error()
		c.log.Warn("update check failed", "err", err)
		return c.status
	}
	c.status.Error = ""
	c.status.Latest = latest
	c.status.URL = url
	c.status.Available = latest != "" && Newer(latest, c.current)
	c.log.Info("update check", "current", c.current, "latest", latest, "available", c.status.Available)
	return c.status
}

// ErrNoRelease means the repository has no published release yet (or is not
// reachable publicly), which GitHub reports as 404.
var ErrNoRelease = errors.New("no release published yet")

func (c *Checker) fetchLatest(ctx context.Context) (version, url string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Adnesia/"+c.current)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", "", ErrNoRelease
	case resp.StatusCode != http.StatusOK:
		return "", "", fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", "", fmt.Errorf("bad release JSON: %w", err)
	}
	if rel.TagName == "" {
		return "", "", ErrNoRelease
	}
	return strings.TrimPrefix(rel.TagName, "v"), rel.HTMLURL, nil
}

// Run checks shortly after start and then every interval until Stop.
func (c *Checker) Run(interval time.Duration) {
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()
	select {
	case <-first.C:
		c.Check(context.Background())
	case <-c.stop:
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.Check(context.Background())
		case <-c.stop:
			return
		}
	}
}

// Stop ends Run.
func (c *Checker) Stop() { c.once.Do(func() { close(c.stop) }) }

// Newer reports whether version a is newer than b. Versions are dotted
// numbers with an optional leading "v" and an optional "-suffix" (a suffix
// such as -rc1 ranks below the bare version). Non-numeric parts compare as 0.
func Newer(a, b string) bool {
	return compare(a, b) > 0
}

func compare(a, b string) int {
	aNums, aSuf := split(a)
	bNums, bSuf := split(b)
	for i := 0; i < len(aNums) || i < len(bNums); i++ {
		var x, y int
		if i < len(aNums) {
			x = aNums[i]
		}
		if i < len(bNums) {
			y = bNums[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	switch {
	case aSuf == bSuf:
		return 0
	case aSuf == "": // 1.0.0 > 1.0.0-rc1
		return 1
	case bSuf == "":
		return -1
	}
	return strings.Compare(aSuf, bSuf)
}

func split(v string) ([]int, string) {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V"))
	suffix := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		suffix = v[i+1:]
		v = v[:i]
	}
	var nums []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		nums = append(nums, n)
	}
	return nums, suffix
}
