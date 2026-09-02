package mitm

import (
	"bytes"
	"regexp"
	"strconv"
)

// The in-page engine is the second half of YouTube ad removal, and the half
// that keeps working when the first half stops.
//
// The response filter matches YouTube's field *names*. That is precise and
// cheap, and it breaks the week a name changes. The in-page engine matches the
// player's *behaviour*: an ad break that starts anyway is driven to its end in
// the client, where the ad is an ordinary <video> whose currentTime can simply
// be moved to the end. Between them, a renamed field costs a few seconds of a
// muted, fast-forwarded ad rather than the full ad.
//
// The same engine skips and mutes SponsorBlock segments, asking Orbis (never
// SponsorBlock directly) for the segment list of whatever is playing. That
// gives any browser that trusts the CA, including the one built into a
// television, what the desktop extension gives a laptop.
//
// It is injected only into YouTube HTML documents, only when the operator has
// turned interception on for YouTube, and it never talks to anything except
// the page it lives in and two same-origin endpoints that Orbis itself
// answers.

// InPageReportPath is the same-origin path the injected engine posts its
// counters to. The proxy answers it locally; the request never leaves the
// network.
const InPageReportPath = "/__orbis/yt-report"

// InPageSegmentsPath is the same-origin path the engine fetches sponsor
// segments from, as ?v=<video id>. Answered locally by the proxy.
const InPageSegmentsPath = "/__orbis/sb"

// nonceRe finds a CSP nonce already present in the document. Reusing it means
// the injected script satisfies YouTube's own Content-Security-Policy, so the
// policy stays intact instead of being stripped to make room for us.
var nonceRe = regexp.MustCompile(`nonce="([A-Za-z0-9+/=_-]{4,64})"`)

// headRe finds the opening <head> tag, with or without attributes.
var headRe = regexp.MustCompile(`(?i)<head[^>]*>`)

// charsetRe finds a charset declaration immediately after <head>. The engine
// goes after it, not before: browsers only honour a charset meta that appears
// within the first kilobyte of the document.
var charsetRe = regexp.MustCompile(`(?is)^\s*<meta\s[^>]*charset[^>]*>`)

// InPageOptions selects what the injected engine does.
type InPageOptions struct {
	// SponsorBlock enables the segment skipper, which fetches segments from
	// InPageSegmentsPath.
	SponsorBlock bool
	// Offset is added to a segment's end when seeking past it, matching the
	// Lounge engine's per-device offset.
	Offset float64
}

// injectPlayerEngine inserts the engine as the first script in the document,
// so it patches JSON.parse before any of YouTube's own code has run and sees
// the very first player response.
func injectPlayerEngine(body []byte, opts InPageOptions) ([]byte, bool) {
	if bytes.Contains(body, []byte(engineMarker)) {
		return body, false
	}
	loc := headRe.FindIndex(body)
	if loc == nil {
		return body, false
	}
	at := loc[1]
	if m := charsetRe.FindIndex(body[at:]); m != nil {
		at += m[1]
	}

	nonce := ""
	if m := nonceRe.FindSubmatch(body); m != nil {
		nonce = ` nonce="` + string(m[1]) + `"`
	}
	cfg := `window.__orbisYTcfg={sb:` + boolJS(opts.SponsorBlock) + `,offset:` + floatJS(opts.Offset) + `};`
	tag := []byte(`<script` + nonce + `>` + cfg + playerEngineJS + `</script>` +
		`<style` + nonce + ` id="` + engineMarker + `-css">` + inPageCSS + `</style>`)

	out := make([]byte, 0, len(body)+len(tag))
	out = append(out, body[:at]...)
	out = append(out, tag...)
	out = append(out, body[at:]...)
	return out, true
}

func boolJS(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// floatJS renders a seek offset as a JS number literal, clamped to a sane
// range so a config typo cannot become a 3000-second jump.
func floatJS(f float64) string {
	if f < 0 || f > 30 {
		f = 0
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

const engineMarker = "orbis-yt-engine"

// inPageCSS removes the ad furniture that has no network request to block:
// overlays drawn over the player, and promoted rows in the feed whose
// renderers arrived under a name the JSON filter did not recognise.
const inPageCSS = `.ytp-ad-overlay-container,.ytp-ad-player-overlay,` +
	`.ytp-ad-player-overlay-layout,.ytp-ad-overlay-slot,.ytp-ad-message-container,` +
	`#player-ads,#masthead-ad,ytd-display-ad-renderer,ytd-promoted-sparkles-web-renderer,` +
	`ytd-promoted-video-renderer,ytd-compact-promoted-video-renderer,ytd-ad-slot-renderer,` +
	`ytd-in-feed-ad-layout-renderer,ytd-banner-promo-renderer,ytd-statement-banner-renderer,` +
	`ytm-promoted-video-renderer,ytm-companion-ad-renderer,ytd-merch-shelf-renderer,` +
	`ytd-engagement-panel-section-list-renderer[target-id="engagement-panel-ads"]` +
	`{display:none!important}` +
	// :has() lives in its own rule on purpose: one unsupported selector
	// invalidates every selector sharing its comma-separated list, and an
	// older TV browser would otherwise lose the whole stylesheet above.
	`ytd-rich-item-renderer:has(ytd-ad-slot-renderer),` +
	`ytd-rich-section-renderer:has(ytd-statement-banner-renderer)` +
	`{display:none!important}`

// playerEngineJS is deliberately written in plain ES5 with no template
// literals: it is embedded in a Go raw string, and it has to run in whatever
// engine a smart TV browser happens to ship.
const playerEngineJS = `(function(){
if(window.__orbisYT)return;
var CFG=window.__orbisYTcfg||{};
var S={v:2,stripped:0,burned:0,skips:0,overlays:0,segments:0,sent:0};
window.__orbisYT=S;

var KEYS=["adPlacements","playerAds","adSlots","adBreakHeartbeatParams","adParams",
"adServingDataEntity","adsEngagementPanels","importantForAds","adBreakParams",
"adRequestParams","playerAdParams","adsData","clientForcedAdParams","adNotify",
"adPlacementRenderer","adSlotMetadata","adLayoutMetadata","adSlotLoggingData",
"adLayoutLoggingData","instreamAdPlayerOverlayRenderer","playerLegacyDesktopWatchAdsRenderer",
"adCpn","clientSideAdConfig","adPlacementConfig","adPlaybackContextParams"];

var RENDERERS=["adSlotRenderer","promotedSparklesWebRenderer","promotedSparklesTextSearchRenderer",
"promotedVideoRenderer","displayAdRenderer","searchPyvRenderer","compactPromotedVideoRenderer",
"instreamVideoAdRenderer","bannerPromoRenderer","statementBannerRenderer","backgroundPromoRenderer",
"brandVideoSingletonRenderer","brandVideoShelfRenderer","inFeedAdLayoutRenderer","carouselAdRenderer",
"primetimePromoRenderer","videoMastheadAdV3Renderer","videoMastheadAdV2Renderer","actionCompanionAdRenderer",
"imageCompanionAdRenderer","videoDisplayFullButtonedAdRenderer","adsFeedRenderer",
"compactPromotedItemRenderer","promotedItemRenderer","shortsAdCardRenderer","adDivergentRenderer",
"featuredPromoRenderer"];

var KEYSET={},RENDSET={},i;
for(i=0;i<KEYS.length;i++)KEYSET[KEYS[i]]=1;
for(i=0;i<RENDERERS.length;i++)RENDSET[RENDERERS[i]]=1;

// A parsed document is only walked when its source text mentions something
// worth walking for. Recursing through every multi-megabyte InnerTube response
// on the off chance would cost more than the ads do.
var MARKER=/"(?:adPlacements|playerAds|adSlots|adBreak|adSlotRenderer|promoted[A-Z]|displayAdRenderer|inFeedAdLayout|adsFeed|MastheadAd|CompanionAd|featuredPromo)/;

function isAdEntry(o){
  if(!o||typeof o!=="object"||Array.isArray(o))return false;
  var k=Object.keys(o),n=0;
  for(var i=0;i<k.length;i++){
    if(k[i]==="clickTrackingParams")continue;
    if(!RENDSET[k[i]])return false;
    n++;
  }
  return n>0;
}

function scrub(node,depth){
  if(!node||typeof node!=="object"||depth>32)return node;
  if(Array.isArray(node)){
    var keep=null;
    for(var i=0;i<node.length;i++){
      if(isAdEntry(node[i])){
        if(keep===null)keep=node.slice(0,i);
        S.stripped++;
        continue;
      }
      var r=scrub(node[i],depth+1);
      if(keep!==null)keep.push(r);
      else if(r!==node[i]){try{node[i]=r;}catch(e){}}
    }
    return keep===null?node:keep;
  }
  for(var k in node){
    if(!Object.prototype.hasOwnProperty.call(node,k))continue;
    if(KEYSET[k]){try{delete node[k];S.stripped++;}catch(e){}continue;}
    var v=node[k];
    if(v&&typeof v==="object"){
      var r=scrub(v,depth+1);
      if(r!==v){try{node[k]=r;}catch(e){}}
    }
  }
  return node;
}

// --- interception of every path a player response can arrive by -------------
var nativeParse=JSON.parse;
JSON.parse=function(text){
  var data=nativeParse.apply(this,arguments);
  try{
    if(typeof text!=="string"||MARKER.test(text))data=scrub(data,0);
  }catch(e){}
  return data;
};
try{
  var nativeJSON=Response.prototype.json;
  Response.prototype.json=function(){
    return nativeJSON.call(this).then(function(d){try{return scrub(d,0);}catch(e){return d;}});
  };
}catch(e){}

// --- the player driver ------------------------------------------------------
function video(){
  return document.querySelector("video.html5-main-video")||document.querySelector("#movie_player video")||document.querySelector("video");
}

var adOn=false,wasMuted=false,lastBurn=0;

function driveAd(p,v){
  var showing=p.classList.contains("ad-showing")||p.classList.contains("ad-interrupting");

  // Overlay banners have their own close button and no bearing on playback.
  var close=document.querySelector(".ytp-ad-overlay-close-button,.ytp-ad-overlay-close-container");
  if(close){close.click();S.overlays++;}

  if(!showing){
    if(adOn){adOn=false;if(v)v.muted=wasMuted;}
    return false;
  }
  if(!adOn){adOn=true;wasMuted=v?v.muted:false;}

  // A skippable ad has a button, and pressing it is the cleanest exit: the
  // player tears the ad down itself and resumes content in one step.
  var b=document.querySelector(".ytp-ad-skip-button,.ytp-ad-skip-button-modern,.ytp-skip-ad-button,.ytp-ad-survey-answer-button");
  if(b&&b.offsetParent!==null){b.click();S.skips++;return true;}

  // Otherwise the ad is an ordinary media element, and the end of it is one
  // assignment away. Muting first keeps the jump silent.
  if(v){
    v.muted=true;
    var d=v.duration;
    if(isFinite(d)&&d>0&&v.currentTime<d-0.15){
      var now=Date.now();
      if(now-lastBurn>250){
        lastBurn=now;
        try{v.currentTime=d;S.burned++;}catch(e){}
        try{if(v.paused)v.play();}catch(e){}
      }
    }
  }
  return true;
}

// --- SponsorBlock segments, via Orbis ---------------------------------------
var SEGS=[],segVid="",segReq=null,sbMuted=false,sbWasMuted=false,lastSeek=0;

function currentVideoId(){
  var m=/[?&]v=([\w-]{11})/.exec(location.search);
  if(m)return m[1];
  m=/\/(?:shorts|embed|live)\/([\w-]{11})/.exec(location.pathname);
  if(m)return m[1];
  try{
    var p=document.getElementById("movie_player");
    if(p&&p.getVideoData){var d=p.getVideoData();if(d&&d.video_id)return d.video_id;}
  }catch(e){}
  return "";
}

function loadSegments(){
  if(!CFG.sb)return;
  var vid=currentVideoId();
  if(vid===segVid)return;
  segVid=vid;SEGS=[];
  if(sbMuted){var v=video();if(v)v.muted=sbWasMuted;sbMuted=false;}
  if(!vid)return;
  try{
    if(segReq){segReq.abort();}
    var x=new XMLHttpRequest();
    segReq=x;
    x.open("GET","` + InPageSegmentsPath + `?v="+vid,true);
    x.onload=function(){
      segReq=null;
      if(x.status!==200||segVid!==vid)return;
      try{
        var d=nativeParse(x.responseText);
        if(d&&d.segments&&d.segments.length)SEGS=d.segments;
      }catch(e){}
    };
    x.onerror=function(){segReq=null;};
    x.send();
  }catch(e){}
}

function segmentAt(t){
  for(var i=0;i<SEGS.length;i++){
    var s=SEGS[i];
    if(t>=s.start-0.5&&t<s.end-1)return s;
  }
  return null;
}

function driveSegments(v){
  if(!SEGS.length||!v||v.paused)return;
  var t=v.currentTime,s=segmentAt(t);
  if(sbMuted&&(!s||s.action!=="mute")){v.muted=sbWasMuted;sbMuted=false;}
  if(!s)return;
  if(s.action==="mute"){
    if(!sbMuted){sbMuted=true;sbWasMuted=v.muted;v.muted=true;S.segments++;}
    return;
  }
  var now=Date.now();
  if(now-lastSeek<1500)return;
  lastSeek=now;
  try{v.currentTime=s.end+(CFG.offset||0);S.segments++;}catch(e){}
}

function drive(){
  try{
    var p=document.getElementById("movie_player");
    if(!p)return;
    var v=video();
    if(driveAd(p,v))return;
    driveSegments(v);
  }catch(e){}
}

var timer=setInterval(drive,250);
setInterval(loadSegments,1000);
window.addEventListener("yt-navigate-finish",loadSegments);
try{
  var mo=new MutationObserver(drive);
  var attach=function(){
    var p=document.getElementById("movie_player");
    if(p){mo.observe(p,{attributes:true,attributeFilter:["class"],subtree:false});return true;}
    return false;
  };
  if(!attach()){
    var w=setInterval(function(){if(attach())clearInterval(w);},1000);
    setTimeout(function(){clearInterval(w);},60000);
  }
}catch(e){}

// --- report counters back to Orbis -----------------------------------------
// Same-origin, answered by the proxy itself, so it is evidence the engine is
// alive rather than telemetry: nothing leaves the network.
var P={stripped:0,burned:0,skips:0,overlays:0,segments:0};
function report(){
  try{
    var d={stripped:S.stripped-P.stripped,burned:S.burned-P.burned,
           skips:S.skips-P.skips,overlays:S.overlays-P.overlays,
           segments:S.segments-P.segments};
    if(d.stripped+d.burned+d.skips+d.overlays+d.segments<=0)return;
    P.stripped=S.stripped;P.burned=S.burned;P.skips=S.skips;P.overlays=S.overlays;P.segments=S.segments;
    S.sent++;
    var body=JSON.stringify(d);
    if(navigator.sendBeacon){navigator.sendBeacon("` + InPageReportPath + `",body);return;}
    var x=new XMLHttpRequest();
    x.open("POST","` + InPageReportPath + `",true);
    x.send(body);
  }catch(e){}
}
setInterval(report,15000);
window.addEventListener("pagehide",report);
})();`
