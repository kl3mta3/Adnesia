package stats

import "testing"

func TestRingWrapsAndClears(t *testing.T) {
	s := New(3)
	for i := 0; i < 5; i++ {
		s.RecordBlocked(0, "h", string(rune('a'+i)))
	}
	snap := s.Snapshot()
	if len(snap.Recent) != 3 || snap.Recent[0].URL != "e" || snap.Recent[2].URL != "c" {
		t.Fatalf("ring newest-first wrong: %+v", snap.Recent)
	}
	s.ClearRecent()
	if n := len(s.Snapshot().Recent); n != 0 {
		t.Fatalf("after clear got %d entries", n)
	}
	s.RecordBlocked(0, "h", "z")
	if r := s.Snapshot().Recent; len(r) != 1 || r[0].URL != "z" {
		t.Fatalf("ring unusable after clear: %+v", r)
	}
}
