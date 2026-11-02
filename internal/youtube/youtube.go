// Package youtube strips YouTube's in-stream video ads.
//
// YouTube serves video ads from the same hosts as the video itself and
// describes them inside the player response, so network/cosmetic filtering
// cannot remove them. This module attacks the player response from two
// independent angles:
//
//  1. Server-side: it rewrites the Innertube player API JSON
//     (/youtubei/v1/player) in flight, deleting the ad-describing fields so
//     the player has no ads to schedule.
//  2. Client-side: it injects a small script into YouTube HTML pages that
//     sanitises the embedded ytInitialPlayerResponse on assignment, hooks
//     fetch/JSON.parse to scrub player responses the SPA loads later, and —
//     as a last resort — skips any ad that still manages to play.
//
// This is an arms race: YouTube changes these shapes periodically, so the
// field list and the script are expected to need updates over time. Keeping
// them isolated here means the rest of Adnesia is unaffected when they do.
package youtube

import (
	"bytes"
	"encoding/json"
	"strings"
)

// adKeys are the player-response fields that describe or schedule ads.
var adKeys = []string{
	"adPlacements",
	"adSlots",
	"playerAds",
	"adBreakHeartbeatParams",
	"adParams",
}

// IsHost reports whether host is a YouTube property whose HTML we should
// inject the strip script into.
func IsHost(host string) bool {
	host = strings.ToLower(host)
	for _, suf := range []string{"youtube.com", "youtube-nocookie.com", "youtubekids.com"} {
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// IsPlayerAPI reports whether a request is to the Innertube player endpoint
// whose JSON response we should strip.
func IsPlayerAPI(host, path string) bool {
	return IsHost(host) && strings.Contains(path, "/youtubei/v1/player")
}

// StripPlayerJSON removes ad fields from a player-API JSON body. It returns
// the new bytes and whether anything was removed. On a parse error it reports
// no change so the original response is passed through untouched.
func StripPlayerJSON(data []byte) ([]byte, bool) {
	// Quick reject: if none of the ad keys even appear, skip the parse.
	if !mentionsAdKey(data) {
		return data, false
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return data, false
	}
	if !scrub(obj) {
		return data, false
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return data, false
	}
	return out, true
}

func mentionsAdKey(data []byte) bool {
	for _, k := range adKeys {
		if bytes.Contains(data, []byte(k)) {
			return true
		}
	}
	return false
}

// scrub deletes ad keys from obj and known nested player-response objects.
// Returns true if it removed anything.
func scrub(obj map[string]any) bool {
	changed := false
	for _, k := range adKeys {
		if _, ok := obj[k]; ok {
			delete(obj, k)
			changed = true
		}
	}
	// Some responses nest the player data under "playerResponse".
	if nested, ok := obj["playerResponse"].(map[string]any); ok {
		if scrub(nested) {
			changed = true
		}
	}
	return changed
}

// Script returns the JavaScript injected into YouTube HTML pages.
func Script() string { return stripScript }

// This is the original script from the build that worked with YouTube,
// restored verbatim.
const stripScript = `
(function(){
  'use strict';
  var AD_KEYS = ['adPlacements','adSlots','playerAds','adBreakHeartbeatParams','adParams'];
  function scrub(o){
    if(!o || typeof o!=='object') return o;
    for(var i=0;i<AD_KEYS.length;i++){ if(AD_KEYS[i] in o){ try{ delete o[AD_KEYS[i]]; }catch(e){} } }
    if(o.playerResponse) scrub(o.playerResponse);
    return o;
  }
  // Sanitise the embedded player response the first watch page carries.
  try{
    var _ypr;
    Object.defineProperty(window,'ytInitialPlayerResponse',{
      configurable:true,
      get:function(){ return _ypr; },
      set:function(v){ _ypr = scrub(v); }
    });
  }catch(e){}
  // Scrub anything parsed via JSON.parse.
  try{
    var _parse = JSON.parse;
    JSON.parse = function(){ return scrub(_parse.apply(this, arguments)); };
  }catch(e){}
  // Scrub player responses the SPA fetches on later navigations.
  if(window.fetch){
    var _fetch = window.fetch;
    window.fetch = function(input, init){
      var url = (typeof input === 'string') ? input : (input && input.url) || '';
      var pr = _fetch.apply(this, arguments);
      if(url.indexOf('/youtubei/v1/player') === -1) return pr;
      return pr.then(function(resp){
        return resp.clone().json().then(function(data){
          scrub(data);
          return new Response(JSON.stringify(data), {status:resp.status, statusText:resp.statusText, headers:resp.headers});
        }).catch(function(){ return resp; });
      });
    };
  }
  // Last resort: skip any ad that still plays.
  setInterval(function(){
    try{
      var player = document.querySelector('.html5-video-player');
      var video = document.querySelector('video');
      if(player && player.classList.contains('ad-showing') && video && isFinite(video.duration)){
        video.currentTime = video.duration;
      }
      var skip = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button');
      if(skip) skip.click();
      var close = document.querySelector('.ytp-ad-overlay-close-button');
      if(close) close.click();
    }catch(e){}
  }, 500);
})();
`
