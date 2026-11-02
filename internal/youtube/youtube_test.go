package youtube

import (
	"encoding/json"
	"testing"
)

func TestIsHost(t *testing.T) {
	yes := []string{"youtube.com", "www.youtube.com", "m.youtube.com", "www.youtube-nocookie.com"}
	no := []string{"example.com", "notyoutube.com", "youtube.com.evil.com"}
	for _, h := range yes {
		if !IsHost(h) {
			t.Errorf("IsHost(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if IsHost(h) {
			t.Errorf("IsHost(%q) = true, want false", h)
		}
	}
}

func TestIsPlayerAPI(t *testing.T) {
	if !IsPlayerAPI("www.youtube.com", "/youtubei/v1/player") {
		t.Error("should recognise the player endpoint")
	}
	if IsPlayerAPI("www.youtube.com", "/watch") {
		t.Error("/watch is not the player endpoint")
	}
	if IsPlayerAPI("example.com", "/youtubei/v1/player") {
		t.Error("non-youtube host should not match")
	}
}

func TestStripPlayerJSON(t *testing.T) {
	in := []byte(`{
		"videoDetails": {"title": "x"},
		"adPlacements": [{"a": 1}],
		"playerAds": [{"b": 2}],
		"adSlots": [1,2,3],
		"streamingData": {"ok": true}
	}`)

	out, changed := StripPlayerJSON(in)
	if !changed {
		t.Fatal("expected ad fields to be stripped")
	}

	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, k := range []string{"adPlacements", "playerAds", "adSlots"} {
		if _, ok := obj[k]; ok {
			t.Errorf("%q should have been removed", k)
		}
	}
	for _, k := range []string{"videoDetails", "streamingData"} {
		if _, ok := obj[k]; !ok {
			t.Errorf("%q should have been preserved", k)
		}
	}
}

func TestStripPlayerJSONNested(t *testing.T) {
	in := []byte(`{"playerResponse":{"adPlacements":[1],"videoDetails":{}}}`)
	out, changed := StripPlayerJSON(in)
	if !changed {
		t.Fatal("expected nested ad fields to be stripped")
	}
	var obj map[string]any
	_ = json.Unmarshal(out, &obj)
	pr := obj["playerResponse"].(map[string]any)
	if _, ok := pr["adPlacements"]; ok {
		t.Error("nested adPlacements should be removed")
	}
}

func TestStripPlayerJSONNoAds(t *testing.T) {
	in := []byte(`{"videoDetails":{"title":"x"},"streamingData":{}}`)
	out, changed := StripPlayerJSON(in)
	if changed {
		t.Error("no change expected when there are no ad fields")
	}
	if string(out) != string(in) {
		t.Error("body should be returned unchanged")
	}
}
