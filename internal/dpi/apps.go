package dpi

import (
	"net/netip"
	"strings"
)

// The service catalogue: hostnames grouped into the applications and
// services a person recognises, each with a category. It drives the app label
// on flows, the Services page, and the assistant's per-service numbers.
//
// Everything here is a public hostname suffix. Nothing about a specific
// network is in it, and unknown names fall back to their registrable domain
// so "other" never swallows the traffic silently.

// Service is one catalogue entry.
type Service struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

type appMatcher struct {
	name     string
	category string
	suffixes []string
	contains []string
}

// Categories, kept short and stable because the UI colours by them.
const (
	CatVideo     = "video"
	CatMusic     = "music"
	CatSocial    = "social"
	CatMessaging = "messaging"
	CatGaming    = "gaming"
	CatWork      = "work"
	CatCloud     = "cloud"
	CatCDN       = "cdn"
	CatUpdates   = "updates"
	CatSmartHome = "smart-home"
	CatShopping  = "shopping"
	CatNews      = "news"
	CatAI        = "ai"
	CatFinance   = "finance"
	CatVPN       = "vpn"
	CatAds       = "ads"
	CatTelemetry = "telemetry"
	CatDev       = "dev"
	CatSearch    = "search"
	CatEmail     = "email"
	CatStorage   = "storage"
	CatPlatform  = "platform"
	CatOther     = "other"
)

var appMatchers = []appMatcher{
	// Video
	{name: "YouTube", category: CatVideo, suffixes: []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt3.ggpht.com", "youtubekids.com"}},
	{name: "Netflix", category: CatVideo, suffixes: []string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com"}},
	{name: "Disney+", category: CatVideo, suffixes: []string{"disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com", "disneystreaming.com"}},
	{name: "Hulu", category: CatVideo, suffixes: []string{"hulu.com", "hulustream.com", "huluim.com"}},
	{name: "Prime Video", category: CatVideo, suffixes: []string{"primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net", "atv-ps.amazon.com"}},
	{name: "Max", category: CatVideo, suffixes: []string{"max.com", "hbomax.com", "hbo.com", "discomax.com"}},
	{name: "Peacock", category: CatVideo, suffixes: []string{"peacocktv.com", "peacocktv.net"}},
	{name: "Paramount+", category: CatVideo, suffixes: []string{"paramountplus.com", "cbsi.com", "cbsivideo.com", "pplusstatic.com"}},
	{name: "Apple TV", category: CatVideo, suffixes: []string{"tv.apple.com", "apple-tv.com"}},
	{name: "Plex", category: CatVideo, suffixes: []string{"plex.tv", "plex.direct"}},
	{name: "Twitch", category: CatVideo, suffixes: []string{"twitch.tv", "ttvnw.net", "jtvnw.net"}},
	{name: "Tubi", category: CatVideo, suffixes: []string{"tubitv.com", "tubi.io", "adrise.tv"}},
	{name: "Pluto TV", category: CatVideo, suffixes: []string{"pluto.tv", "plutotv.net"}},
	{name: "Roku", category: CatVideo, suffixes: []string{"roku.com", "rokutime.com", "roku.co", "ravm.tv"}},
	{name: "Crunchyroll", category: CatVideo, suffixes: []string{"crunchyroll.com", "vrv.co"}},
	{name: "Vimeo", category: CatVideo, suffixes: []string{"vimeo.com", "vimeocdn.com"}},
	{name: "Bilibili", category: CatVideo, suffixes: []string{"bilibili.com", "bilivideo.com", "hdslb.com", "biliapi.net"}},
	{name: "iQIYI", category: CatVideo, suffixes: []string{"iqiyi.com", "iq.com", "qy.net"}},
	{name: "Youku", category: CatVideo, suffixes: []string{"youku.com", "ykimg.com"}},
	{name: "Tencent Video", category: CatVideo, suffixes: []string{"v.qq.com", "qqvideo.tc.qq.com", "video.qq.com"}},

	// Music and audio
	{name: "Spotify", category: CatMusic, suffixes: []string{"spotify.com", "scdn.co", "spotifycdn.com", "pscdn.co"}},
	{name: "Apple Music", category: CatMusic, suffixes: []string{"music.apple.com", "itunes.apple.com", "audio-ssl.itunes.apple.com"}},
	{name: "Amazon Music", category: CatMusic, suffixes: []string{"music.amazon.com", "amazonmusic.com"}},
	{name: "YouTube Music", category: CatMusic, suffixes: []string{"music.youtube.com"}},
	{name: "SoundCloud", category: CatMusic, suffixes: []string{"soundcloud.com", "sndcdn.com"}},
	{name: "Tidal", category: CatMusic, suffixes: []string{"tidal.com", "tidalhifi.com"}},
	{name: "Pandora", category: CatMusic, suffixes: []string{"pandora.com", "p-cdn.us"}},
	{name: "Audible", category: CatMusic, suffixes: []string{"audible.com", "audible.co.uk"}},
	{name: "Sonos", category: CatMusic, suffixes: []string{"sonos.com", "sonos.radio", "ws.sonos.com"}},
	{name: "TuneIn", category: CatMusic, suffixes: []string{"tunein.com", "radiotime.com"}},

	// Social
	{name: "Meta", category: CatSocial, suffixes: []string{"facebook.com", "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com"}},
	{name: "Instagram", category: CatSocial, suffixes: []string{"instagram.com", "cdninstagram.com"}},
	{name: "Threads", category: CatSocial, suffixes: []string{"threads.net"}},
	{name: "TikTok", category: CatSocial, suffixes: []string{"tiktok.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokv.com", "byteoversea.com", "musical.ly", "ibytedtos.com", "ibyteimg.com", "bytedance.com"}},
	{name: "X/Twitter", category: CatSocial, suffixes: []string{"twitter.com", "x.com", "twimg.com", "t.co"}},
	{name: "Reddit", category: CatSocial, suffixes: []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"}},
	{name: "Snapchat", category: CatSocial, suffixes: []string{"snapchat.com", "sc-cdn.net", "snap.com"}},
	{name: "Pinterest", category: CatSocial, suffixes: []string{"pinterest.com", "pinimg.com"}},
	{name: "LinkedIn", category: CatSocial, suffixes: []string{"linkedin.com", "licdn.com"}},
	{name: "Weibo", category: CatSocial, suffixes: []string{"weibo.com", "weibo.cn", "sinaimg.cn"}},
	{name: "Xiaohongshu", category: CatSocial, suffixes: []string{"xiaohongshu.com", "xhscdn.com"}},
	{name: "Douyin", category: CatSocial, suffixes: []string{"douyin.com", "douyinpic.com", "douyinvod.com"}},
	{name: "Tumblr", category: CatSocial, suffixes: []string{"tumblr.com"}},

	// Messaging and calls
	{name: "WhatsApp", category: CatMessaging, suffixes: []string{"whatsapp.net", "whatsapp.com"}},
	{name: "Messenger", category: CatMessaging, suffixes: []string{"messenger.com"}},
	{name: "Telegram", category: CatMessaging, suffixes: []string{"telegram.org", "t.me", "telegram.me", "telesco.pe"}},
	{name: "Signal", category: CatMessaging, suffixes: []string{"signal.org", "whispersystems.org"}},
	{name: "Discord", category: CatMessaging, suffixes: []string{"discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media"}},
	{name: "Slack", category: CatMessaging, suffixes: []string{"slack.com", "slack-edge.com", "slack-msgs.com"}},
	{name: "Zoom", category: CatMessaging, suffixes: []string{"zoom.us", "zoom.com", "zoomgov.com"}},
	{name: "Teams", category: CatMessaging, suffixes: []string{"teams.microsoft.com", "teams.live.com", "skype.com", "skypeassets.com"}},
	{name: "WeChat", category: CatMessaging, suffixes: []string{"wechat.com", "weixin.qq.com", "wx.qq.com", "wechatapp.com", "qpic.cn"}},
	{name: "iMessage/FaceTime", category: CatMessaging, suffixes: []string{"ess.apple.com", "ids.apple.com", "facetime.apple.com"}},
	{name: "Google Meet", category: CatMessaging, suffixes: []string{"meet.google.com", "meet.googleapis.com"}},
	{name: "Line", category: CatMessaging, suffixes: []string{"line.me", "line-apps.com", "line-scdn.net"}},

	// Gaming
	{name: "Steam", category: CatGaming, suffixes: []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamusercontent.com"}},
	{name: "Epic Games", category: CatGaming, suffixes: []string{"epicgames.com", "unrealengine.com", "epicgames.dev"}},
	{name: "PlayStation", category: CatGaming, suffixes: []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "np.dl.playstation.net"}},
	{name: "Xbox", category: CatGaming, suffixes: []string{"xboxlive.com", "xbox.com", "xboxservices.com"}},
	{name: "Nintendo", category: CatGaming, suffixes: []string{"nintendo.net", "nintendo.com", "nintendowifi.net"}},
	{name: "Roblox", category: CatGaming, suffixes: []string{"roblox.com", "rbxcdn.com", "rbx.com"}},
	{name: "Minecraft", category: CatGaming, suffixes: []string{"minecraft.net", "mojang.com", "minecraftservices.com"}},
	{name: "Riot Games", category: CatGaming, suffixes: []string{"riotgames.com", "leagueoflegends.com", "riotcdn.net", "valorant.com"}},
	{name: "Blizzard", category: CatGaming, suffixes: []string{"blizzard.com", "battle.net", "blzstatic.cn"}},
	{name: "EA", category: CatGaming, suffixes: []string{"ea.com", "origin.com"}},
	{name: "Ubisoft", category: CatGaming, suffixes: []string{"ubisoft.com", "ubi.com"}},
	{name: "GeForce Now", category: CatGaming, suffixes: []string{"nvidiagrid.net", "geforcenow.com"}},

	// Work and productivity
	{name: "Google Workspace", category: CatWork, suffixes: []string{"docs.google.com", "drive.google.com", "mail.google.com", "calendar.google.com", "sheets.google.com", "slides.google.com"}},
	{name: "Microsoft 365", category: CatWork, suffixes: []string{"office.com", "office365.com", "office.net", "sharepoint.com", "onedrive.com", "outlook.com", "outlook.office.com", "live.com"}},
	{name: "Notion", category: CatWork, suffixes: []string{"notion.so", "notion.site", "notion-static.com"}},
	{name: "Figma", category: CatWork, suffixes: []string{"figma.com"}},
	{name: "Atlassian", category: CatWork, suffixes: []string{"atlassian.com", "atlassian.net", "jira.com", "bitbucket.org"}},
	{name: "Dropbox", category: CatStorage, suffixes: []string{"dropbox.com", "dropboxusercontent.com", "dropboxstatic.com"}},
	{name: "iCloud", category: CatStorage, suffixes: []string{"icloud.com", "icloud-content.com", "apple-cloudkit.com"}},
	{name: "Box", category: CatStorage, suffixes: []string{"box.com", "boxcdn.net"}},
	{name: "Backblaze", category: CatStorage, suffixes: []string{"backblaze.com", "backblazeb2.com"}},
	{name: "Synology", category: CatStorage, suffixes: []string{"synology.com", "synology.me", "quickconnect.to", "synologydownload.com"}},

	// AI
	{name: "OpenAI", category: CatAI, suffixes: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"}},
	{name: "Anthropic", category: CatAI, suffixes: []string{"anthropic.com", "claude.ai"}},
	{name: "Gemini", category: CatAI, suffixes: []string{"gemini.google.com", "generativelanguage.googleapis.com"}},
	{name: "OpenRouter", category: CatAI, suffixes: []string{"openrouter.ai"}},
	{name: "Perplexity", category: CatAI, suffixes: []string{"perplexity.ai"}},
	{name: "Hugging Face", category: CatAI, suffixes: []string{"huggingface.co", "hf.co"}},

	// Shopping
	{name: "Amazon", category: CatShopping, suffixes: []string{"amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "media-amazon.com", "ssl-images-amazon.com", "images-amazon.com", "amazon.jobs"}},
	{name: "eBay", category: CatShopping, suffixes: []string{"ebay.com", "ebaystatic.com", "ebayimg.com"}},
	{name: "Temu", category: CatShopping, suffixes: []string{"temu.com", "kwcdn.com"}},
	{name: "Shein", category: CatShopping, suffixes: []string{"shein.com", "ltwebstatic.com"}},
	{name: "Taobao/Tmall", category: CatShopping, suffixes: []string{"taobao.com", "tmall.com", "alicdn.com", "alibaba.com", "aliexpress.com", "mmstat.com"}},
	{name: "JD", category: CatShopping, suffixes: []string{"jd.com", "360buyimg.com"}},
	{name: "Walmart", category: CatShopping, suffixes: []string{"walmart.com", "walmartimages.com"}},
	{name: "Target", category: CatShopping, suffixes: []string{"target.com"}},
	{name: "Costco", category: CatShopping, suffixes: []string{"costco.com"}},
	{name: "Instacart", category: CatShopping, suffixes: []string{"instacart.com"}},
	{name: "DoorDash", category: CatShopping, suffixes: []string{"doordash.com"}},
	{name: "Uber", category: CatShopping, suffixes: []string{"uber.com", "ubereats.com"}},

	// News and reading
	{name: "Wikipedia", category: CatNews, suffixes: []string{"wikipedia.org", "wikimedia.org"}},
	{name: "New York Times", category: CatNews, suffixes: []string{"nytimes.com", "nyt.com"}},
	{name: "WSJ", category: CatNews, suffixes: []string{"wsj.com", "wsj.net", "dowjones.com"}},
	{name: "BBC", category: CatNews, suffixes: []string{"bbc.co.uk", "bbc.com", "bbci.co.uk"}},
	{name: "CNN", category: CatNews, suffixes: []string{"cnn.com", "cnn.io"}},
	{name: "Substack", category: CatNews, suffixes: []string{"substack.com", "substackcdn.com"}},
	{name: "Medium", category: CatNews, suffixes: []string{"medium.com"}},

	// Finance
	{name: "PayPal", category: CatFinance, suffixes: []string{"paypal.com", "paypalobjects.com", "venmo.com"}},
	{name: "Chase", category: CatFinance, suffixes: []string{"chase.com", "jpmorgan.com"}},
	{name: "Plaid", category: CatFinance, suffixes: []string{"plaid.com"}},
	{name: "Stripe", category: CatFinance, suffixes: []string{"stripe.com", "stripe.network"}},
	{name: "Coinbase", category: CatFinance, suffixes: []string{"coinbase.com"}},
	{name: "Robinhood", category: CatFinance, suffixes: []string{"robinhood.com"}},

	// Smart home and IoT
	{name: "Ring", category: CatSmartHome, suffixes: []string{"ring.com", "ring-alarm.com"}},
	{name: "Nest", category: CatSmartHome, suffixes: []string{"nest.com", "dropcam.com", "home.nest.com"}},
	{name: "Alexa", category: CatSmartHome, suffixes: []string{"alexa.amazon.com", "amazonalexa.com", "avs-alexa-na.amazon.com", "device-metrics-us.amazon.com", "a2z.com"}},
	{name: "Google Home", category: CatSmartHome, suffixes: []string{"home.google.com", "clients.google.com"}},
	{name: "Philips Hue", category: CatSmartHome, suffixes: []string{"meethue.com", "philips-hue.com"}},
	{name: "TP-Link", category: CatSmartHome, suffixes: []string{"tplinkcloud.com", "tplinknbu.com", "tplinkra.com", "tp-link.com"}},
	{name: "Tuya", category: CatSmartHome, suffixes: []string{"tuyaus.com", "tuyacn.com", "tuyaeu.com", "tuya.com"}},
	{name: "Wyze", category: CatSmartHome, suffixes: []string{"wyze.com", "wyzecam.com"}},
	{name: "Samsung SmartThings", category: CatSmartHome, suffixes: []string{"smartthings.com", "samsungiotcloud.com"}},
	{name: "Samsung TV", category: CatSmartHome, suffixes: []string{"samsungcloudsolution.com", "samsungcloudsolution.net", "samsungotn.net", "samsungqbe.com", "samsungrm.net", "internet.apps.samsung.com", "samsungacr.com"}},
	{name: "LG TV", category: CatSmartHome, suffixes: []string{"lgtvsdp.com", "lgappstv.com", "lge.com", "lgtvcommon.com"}},
	{name: "Vizio", category: CatSmartHome, suffixes: []string{"vizio.com", "vizioportal.com", "smartcast.com"}},
	{name: "Tesla", category: CatSmartHome, suffixes: []string{"tesla.com", "teslamotors.com"}},
	{name: "Prusa", category: CatSmartHome, suffixes: []string{"prusa3d.com", "prusa.io"}},
	{name: "Eufy", category: CatSmartHome, suffixes: []string{"eufylife.com", "anker.com", "anker-in.com"}},
	{name: "Roborock", category: CatSmartHome, suffixes: []string{"roborock.com"}},
	{name: "Xiaomi", category: CatSmartHome, suffixes: []string{"mi.com", "xiaomi.com", "xiaomi.net", "miui.com", "mi-img.com"}},

	// Platforms: OS vendors, updates, push
	{name: "Apple", category: CatPlatform, suffixes: []string{"apple.com", "mzstatic.com", "cdn-apple.com", "apple-dns.net", "aaplimg.com", "push.apple.com", "apple-mapkit.com"}},
	{name: "Apple Updates", category: CatUpdates, suffixes: []string{"mesu.apple.com", "swcdn.apple.com", "swdist.apple.com", "gdmf.apple.com", "updates.cdn-apple.com", "appldnld.apple.com"}},
	{name: "Google", category: CatPlatform, suffixes: []string{"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "ggpht.com", "gvt1.com", "gvt2.com", "1e100.net", "google.com.hk", "googlezip.net", "withgoogle.com"}},
	{name: "Google Play", category: CatUpdates, suffixes: []string{"play.google.com", "play.googleapis.com", "android.com", "gvt3.com", "play-fe.googleapis.com"}},
	{name: "Microsoft", category: CatPlatform, suffixes: []string{"microsoft.com", "windows.net", "msftncsi.com", "msedge.net", "microsoftonline.com", "msftconnecttest.com", "msn.com", "bing.com", "azureedge.net", "aadcdn.net", "xboxab.com"}},
	{name: "Windows Update", category: CatUpdates, suffixes: []string{"windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com", "windowsupdate.microsoft.com"}},
	{name: "Ubuntu/Debian", category: CatUpdates, suffixes: []string{"ubuntu.com", "debian.org", "canonical.com", "snapcraft.io", "launchpad.net", "raspberrypi.com", "raspberrypi.org"}},
	{name: "Mozilla", category: CatPlatform, suffixes: []string{"mozilla.org", "mozilla.net", "mozilla.com", "firefox.com"}},
	{name: "Brave", category: CatPlatform, suffixes: []string{"brave.com", "bravesoftware.com"}},
	{name: "NVIDIA", category: CatUpdates, suffixes: []string{"nvidia.com", "gfe.nvidia.com"}},
	{name: "Samsung", category: CatPlatform, suffixes: []string{"samsung.com", "samsungapps.com", "samsungdm.com", "ospserver.net", "samsungelectronics.com"}},
	{name: "Huawei", category: CatPlatform, suffixes: []string{"huawei.com", "hicloud.com", "dbankcloud.com", "hwcloudtest.cn"}},
	{name: "Tencent", category: CatPlatform, suffixes: []string{"qq.com", "gtimg.com", "qlogo.cn", "tencent.com", "myqcloud.com", "tencent-cloud.net"}},
	{name: "Baidu", category: CatSearch, suffixes: []string{"baidu.com", "bdstatic.com", "bdimg.com"}},
	{name: "Alibaba Cloud", category: CatCloud, suffixes: []string{"aliyun.com", "aliyuncs.com", "alibabadns.com", "alibabausercontent.com"}},
	{name: "DuckDuckGo", category: CatSearch, suffixes: []string{"duckduckgo.com"}},

	// Cloud and CDN
	{name: "AWS", category: CatCloud, suffixes: []string{"amazonaws.com", "awsstatic.com", "cloudfront.net", "amazontrust.com", "awsdns.com"}},
	{name: "Azure", category: CatCloud, suffixes: []string{"azure.com", "azure.net", "azurewebsites.net", "trafficmanager.net", "azurefd.net", "blob.core.windows.net", "azure-devices.net"}},
	{name: "Google Cloud", category: CatCloud, suffixes: []string{"googlecloud.com", "run.app", "appspot.com", "firebaseio.com", "firebaseapp.com", "cloudfunctions.net"}},
	{name: "Cloudflare", category: CatCDN, suffixes: []string{"cloudflare.com", "cloudflare-dns.com", "one.one.one.one", "cloudflareinsights.com", "cloudflarestream.com", "cloudflare.net", "workers.dev", "pages.dev", "cloudflareaccess.com", "cfargotunnel.com"}},
	{name: "Akamai", category: CatCDN, suffixes: []string{"akamai.net", "akamaized.net", "akamaihd.net", "akamaiedge.net", "akadns.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net"}},
	{name: "Fastly", category: CatCDN, suffixes: []string{"fastly.net", "fastlylb.net", "fastly-edge.com"}},
	{name: "jsDelivr/unpkg", category: CatCDN, suffixes: []string{"jsdelivr.net", "unpkg.com", "cdnjs.com"}},
	{name: "Vercel", category: CatCloud, suffixes: []string{"vercel.app", "vercel.com", "vercel-dns.com"}},
	{name: "Netlify", category: CatCloud, suffixes: []string{"netlify.app", "netlify.com"}},
	{name: "DigitalOcean", category: CatCloud, suffixes: []string{"digitalocean.com", "digitaloceanspaces.com"}},
	{name: "Hetzner", category: CatCloud, suffixes: []string{"hetzner.com", "hetzner.cloud", "your-server.de"}},
	{name: "Oracle Cloud", category: CatCloud, suffixes: []string{"oraclecloud.com", "oracle.com"}},

	// Dev
	{name: "GitHub", category: CatDev, suffixes: []string{"github.com", "githubusercontent.com", "githubassets.com", "github.io", "ghcr.io", "githubapp.com"}},
	{name: "GitLab", category: CatDev, suffixes: []string{"gitlab.com", "gitlab.io"}},
	{name: "Docker", category: CatDev, suffixes: []string{"docker.io", "docker.com", "dockerhub.com"}},
	{name: "npm/PyPI", category: CatDev, suffixes: []string{"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org", "yarnpkg.com"}},
	{name: "Go modules", category: CatDev, suffixes: []string{"golang.org", "go.dev", "proxy.golang.org", "sum.golang.org"}},
	{name: "Homebrew", category: CatDev, suffixes: []string{"brew.sh"}},
	{name: "Tailscale", category: CatVPN, suffixes: []string{"tailscale.com", "tailscale.io", "ts.net"}},
	{name: "WireGuard/VPN", category: CatVPN, suffixes: []string{"nordvpn.com", "expressvpn.com", "mullvad.net", "protonvpn.com", "surfshark.com", "privateinternetaccess.com", "zscaler.net", "zscalertwo.net"}},
	{name: "Proton", category: CatEmail, suffixes: []string{"proton.me", "protonmail.com", "protonmail.ch"}},
	{name: "Gmail", category: CatEmail, suffixes: []string{"gmail.com", "googlemail.com"}},
	{name: "Fastmail", category: CatEmail, suffixes: []string{"fastmail.com", "messagingengine.com"}},

	// Debrid and media tooling seen on home labs
	{name: "AllDebrid", category: CatVideo, suffixes: []string{"alldebrid.com", "debrid.link"}},
	{name: "Real-Debrid", category: CatVideo, suffixes: []string{"real-debrid.com"}},
	{name: "Trakt", category: CatVideo, suffixes: []string{"trakt.tv"}},
	{name: "TMDB", category: CatVideo, suffixes: []string{"themoviedb.org", "tmdb.org"}},
	{name: "SponsorBlock", category: CatVideo, suffixes: []string{"sponsor.ajay.app"}},
	{name: "Usenet", category: CatStorage, suffixes: []string{"easynews.com", "eweka.nl", "newshosting.com", "usenetserver.com", "frugalusenet.com", "giganews.com"}},

	// Ads and telemetry: pattern matches, because the hostnames are endless.
	{name: "Ad/Tracking", category: CatAds, contains: []string{"doubleclick", "googlesyndication", "googleadservices", "adsystem", "scorecardresearch", "adnxs", "criteo", "taboola", "outbrain", "moatads", "adsafeprotected", "rubiconproject", "pubmatic", "openx", "amazon-adsystem", "adcolony", "applovin", "unityads", "chartboost", "vungle", "inmobi", "smaato", "adform", "casalemedia", "demdex", "everesttech", "quantserve", "bluekai", "krxd.net", "liadm.com", "adsrvr.org", "yieldmo", "sharethrough", "tremorhub", "spotxchange", "innovid", "freewheel", "fwmrm", "imrworldwide", "advertising.com", "ads.yahoo", "adtech", "3lift", "indexww", "media.net", "gumgum", "33across", "bidswitch", "mgid", "revcontent", "zemanta"}},
	{name: "Telemetry", category: CatTelemetry, contains: []string{"telemetry", "analytics", "crashlytics", "sentry.io", "bugsnag", "mixpanel", "segment.io", "segment.com", "amplitude", "appsflyer", "branch.io", "app-measurement", "firebaselogging", "launchdarkly", "newrelic", "datadoghq", "hotjar", "fullstory", "clarity.ms", "braze.com", "onesignal", "adjust.com", "kochava", "singular.net", "split.io", "optimizely", "appdynamics", "dynatrace", "metrics.", "logging.", "cookiepro", "cookielaw", "onetrust", "trustarc", "usercentrics"}},
}

// suffixIndex speeds up exact and suffix lookups: every label boundary of the
// hostname is tried against this map, so a 5-label name costs five lookups
// instead of a scan across a few hundred suffixes.
var suffixIndex = func() map[string]*appMatcher {
	idx := make(map[string]*appMatcher, 1024)
	for i := range appMatchers {
		m := &appMatchers[i]
		for _, s := range m.suffixes {
			idx[strings.ToLower(s)] = m
		}
	}
	return idx
}()

// Classify maps a hostname to its service. The second result is false when
// the name is not in the catalogue.
func Classify(host string) (Service, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return Service{}, false
	}
	// Longest suffix first: "music.youtube.com" is YouTube Music before it
	// is YouTube; "tv.apple.com" is Apple TV before it is Apple.
	for rest := h; rest != ""; {
		if m, ok := suffixIndex[rest]; ok {
			return Service{Name: m.name, Category: m.category}, true
		}
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
	}
	for i := range appMatchers {
		m := &appMatchers[i]
		for _, c := range m.contains {
			if strings.Contains(h, c) {
				return Service{Name: m.name, Category: m.category}, true
			}
		}
	}
	return Service{}, false
}

// ServiceFor is Classify with the fallback the rollups need: an unknown name
// becomes its registrable domain in the "other" category, an empty name
// becomes "Unresolved", so no traffic is dropped from the totals.
func ServiceFor(host string) Service {
	if svc, ok := Classify(host); ok {
		return svc
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return Service{Name: "Unresolved", Category: CatOther}
	}
	// A bare address is not a domain; "192.168.50.75" must not become "50.75".
	if addr, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
			return Service{Name: "Local network", Category: CatOther}
		}
		return Service{Name: "Unresolved", Category: CatOther}
	}
	return Service{Name: RegistrableDomain(h), Category: CatOther}
}

// twoLevelSuffixes are public suffixes with two labels, so "bbc.co.uk" is not
// collapsed to "co.uk". Not the whole public suffix list; the common tail.
var twoLevelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "co.nz": true, "co.jp": true, "ne.jp": true, "or.jp": true,
	"com.br": true, "com.cn": true, "net.cn": true, "org.cn": true, "com.hk": true, "com.tw": true, "com.sg": true,
	"co.kr": true, "co.in": true, "co.za": true, "com.mx": true, "com.ar": true, "com.tr": true, "co.id": true,
	"com.my": true, "com.ph": true, "com.vn": true, "com.sa": true, "com.eg": true, "com.pk": true, "com.ng": true,
	"github.io": true, "gitlab.io": true, "pages.dev": true, "workers.dev": true, "vercel.app": true, "netlify.app": true,
	"herokuapp.com": true, "azurewebsites.net": true, "cloudfront.net": true, "amazonaws.com": true, "run.app": true,
	"web.app": true, "firebaseapp.com": true, "blogspot.com": true, "wordpress.com": true, "myshopify.com": true,
}

// RegistrableDomain reduces a hostname to the part someone registered:
// "cdn.assets.example.com" -> "example.com", "news.bbc.co.uk" -> "bbc.co.uk".
func RegistrableDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	labels := strings.Split(h, ".")
	if len(labels) <= 2 {
		return h
	}
	tail := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if twoLevelSuffixes[tail] && len(labels) >= 3 {
		return labels[len(labels)-3] + "." + tail
	}
	return tail
}

// Catalogue lists every known service for the UI and the assistant.
func Catalogue() []Service {
	out := make([]Service, 0, len(appMatchers))
	for _, m := range appMatchers {
		out = append(out, Service{Name: m.name, Category: m.category})
	}
	return out
}
