package adblock

// streamingAdDomains is the built-in "streaming ads and viewing telemetry"
// list: the hosts that smart televisions, streaming sticks and media apps use
// only to fetch advertising or to report what is being watched.
//
// The bar for inclusion is strict, because a wrong entry here breaks a stream
// for a household that will not know why: a host is listed only if nothing a
// viewer wants depends on it. That excludes, deliberately, every server-side
// ad-insertion origin (dai.google.com and its peers serve the programme and
// the ad from the same URL), the app stores and firmware endpoints, and any
// host a player is known to wait on before it will start. Those cases are
// handled by the in-stream filter and the Lounge engine, where the ad can be
// separated from the content; a DNS sinkhole cannot make that distinction.
//
// Entries match the domain and every subdomain.
var streamingAdDomains = []string{
	// Samsung Tizen: ad decisioning and automatic content recognition (ACR).
	"samsungads.com",
	"samsungadhub.com",
	"samsungacr.com",
	"ads.samsung.com",
	"smartclip.net",
	"smartclip.com",
	"samsungrm.net",

	// LG webOS: LG Ads and the ACR reporting behind "Live Plus".
	"lgads.tv",
	"lgsmartad.com",
	"ad.lgappstv.com",
	"ibs.lgappstv.com",
	"rdx2.lgtvsdp.com",
	"lgtvonline.lge.com",

	// Roku: the ad platform, measurement and the log collectors. The device
	// services host (cloudservices.roku.com) is not here; search and the
	// channel store depend on it.
	"advertising.roku.com",
	"ads.roku.com",
	"logs.roku.com",
	"scribe.logs.roku.com",
	"giga.logs.roku.com",
	"ravm.tv",

	// Amazon Fire TV: the ad system and the device metrics collectors.
	"amazon-adsystem.com",
	"mads.amazon.com",
	"mads-eu.amazon.com",
	"device-metrics-us.amazon.com",
	"device-metrics-us-2.amazon.com",
	"fls-na.amazon.com",
	"fls-eu.amazon.com",
	"fls-fe.amazon.com",
	"unagi.amazon.com",
	"unagi-na.amazon.com",
	"unagi-eu.amazon.com",
	"unagi-fe.amazon.com",

	// Vizio SmartCast and the ACR vendors that ship inside several brands
	// (Inscape in Vizio, Samba in Sony, Philips, Sharp and TCL, Alphonso in
	// LG and Hisense app bundles).
	"tvinteractive.tv",
	"inscape.tv",
	"samba.tv",
	"sambatv.com",
	"alphonso.tv",
	"alphonso.com",

	// Hisense VIDAA and TCL: the advertising subsidiaries only.
	"vidaa-ads.com",
	"hisense-ads.com",
	"tcl-ads.com",

	// Xbox and Windows home-screen promotions, separate from the game and
	// account services.
	"arc.msn.com",
	"ris.api.iris.microsoft.com",

	// Music apps: the ad-event trackers, which are separate from playback.
	"adeventtracker.spotify.com",
	"ads-fa.spotify.com",
	"adstudio.spotify.com",
	"ads.pandora.com",
	"adserver.pandora.com",
	"ad.deezer.com",

	// Twitch analytics collectors. The stream, chat and the API stay open.
	"science.twitch.tv",
	"spade.twitch.tv",

	// Viewability and audience measurement: pixels and beacons that report
	// an ad was seen. A player never waits on these to start.
	"adsafeprotected.com",
	"moatads.com",
	"doubleverify.com",
	"scorecardresearch.com",
	"imrworldwide.com",
	"samplicio.us",
	"ad.gt",
	"iqzone.com",
}

// streamingNeverBlock is the safety net behind the list above: hosts that a
// stream, an app store or a device depends on, checked in a test so nobody
// can add one to the list by mistake.
var streamingNeverBlock = []string{
	// Server-side and client-side ad *decision* servers. A player that does
	// its own VAST/VMAP call waits on these before the break can end, and
	// several of them serve the programme itself. Blocking them is how a
	// household ends up with "having trouble playing" on the first ad break.
	"dai.google.com",
	"pubads.g.doubleclick.net",
	"fwmrm.net",
	"freewheel.tv",
	"innovid.com",
	"springserve.com",
	"spotxchange.com",
	"tremorhub.com",
	"adrise.tv",
	"uplynk.com",
	"yospace.com",
	"mediatailor.us-east-1.amazonaws.com",
	// The apps those servers sit behind.
	"hulu.com",
	"sling.com",
	"peacocktv.com",
	"pluto.tv",
	"tubi.tv",
	"tubitv.com",
	"paramountplus.com",
	"plex.tv",
	"xumo.com",
	"crackle.com",
	"philo.com",
	"fubo.tv",
	"disneyplus.com",
	"max.com",
	"netflix.com",
	// Device services, app stores, firmware and playback for each platform.
	"cloudservices.roku.com",
	"api.roku.com",
	"roku.com",
	"samsungcloudsolution.com",
	"samsungotn.net",
	"samsungcloudsolution.net",
	"samsung.com",
	"lgappstv.com",
	"lgtvsdp.com",
	"lge.com",
	"vidaahub.com",
	"vidaa.com",
	"tcl.com",
	"hisense.com",
	"spclient.wg.spotify.com",
	"audio-ak-spotify-com.akamaized.net",
	"usher.ttvnw.net",
	"video-weaver.hls.ttvnw.net",
	"gql.twitch.tv",
	"api.twitch.tv",
	"xboxlive.com",
	"playstation.net",
	"amazonvideo.com",
	"primevideo.com",
	"aiv-cdn.net",
	"atv-ps.amazon.com",
	"api.amazonvideo.com",
	"appletv.apple.com",
	"androidtv-watchnext-pa.googleapis.com",
	"play.googleapis.com",
	"googlevideo.com",
	"youtube.com",
	// Mobile-game ad SDKs. Rewarded-ad games hang without them, and they
	// are not streaming hosts in any case.
	"unityads.unity3d.com",
	"vungle.com",
}

// StreamingAdDomainCount is exposed for the UI, so the switch can say how
// many hosts it controls.
func StreamingAdDomainCount() int { return len(streamingAdDomains) }

// DoHBypassDomainCount is exposed for the UI alongside the streaming count.
func DoHBypassDomainCount() int { return len(dohBypassDomains) }
