package bypass

import (
	"io"
	"log/slog"
	"testing"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestDefaultsMatch(t *testing.T) {
	m, err := NewManager(t.TempDir(), nil, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("store.steampowered.com") {
		t.Error("steam subdomain should be bypassed by default")
	}
	if !m.Match("login.live.com") {
		t.Error("login.live.com should be bypassed by default")
	}
	if m.Match("example.com") {
		t.Error("example.com should not be bypassed")
	}
}

func TestAddPersistReload(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(dir, nil, quietLog())

	if m.Match("mybank.example") {
		t.Fatal("precondition: should not match yet")
	}
	if err := m.Add("*.mybank.example"); err != nil {
		t.Fatal(err)
	}
	if !m.Match("secure.mybank.example") {
		t.Error("added pattern should match after Add")
	}

	// A fresh manager over the same dir should load the persisted addition.
	m2, _ := NewManager(dir, nil, quietLog())
	if !m2.Match("secure.mybank.example") {
		t.Error("added pattern should persist across reload")
	}
}

func TestRemoveOnlyRuntimeAdditions(t *testing.T) {
	m, _ := NewManager(t.TempDir(), nil, quietLog())

	_ = m.Add("extra.example")
	removed, err := m.Remove("extra.example")
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("runtime addition should be removable")
	}
	if m.Match("extra.example") {
		t.Error("removed pattern should no longer match")
	}

	// Defaults are not removable through Remove.
	removed, _ = m.Remove("*.steampowered.com")
	if removed {
		t.Error("defaults should not be removable")
	}
	if !m.Match("store.steampowered.com") {
		t.Error("default should still match after a no-op remove")
	}
}

func TestUserPatternsFromConfig(t *testing.T) {
	m, _ := NewManager(t.TempDir(), []string{"*.corp.internal"}, quietLog())
	if !m.Match("vpn.corp.internal") {
		t.Error("config user pattern should match")
	}
	_, user, _ := m.Lists()
	if len(user) != 1 || user[0] != "*.corp.internal" {
		t.Errorf("Lists should report the user pattern, got %v", user)
	}
}
