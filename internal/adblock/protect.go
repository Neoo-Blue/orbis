package adblock

import "strings"

// protectedDomains are names an automated blocker must never touch: taking
// one out breaks updates, logins, payments or the network itself for every
// device, and no threat finding is worth that without a person deciding.
var protectedDomains = []string{
	"apple.com", "icloud.com", "icloud.net", "apple-dns.net", "mzstatic.com", "aaplimg.com",
	"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "gvt2.com", "youtube.com", "ytimg.com",
	"microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "office365.com", "msftconnecttest.com", "msedge.net", "azure.com", "azureedge.net", "microsoftonline.com",
	"amazon.com", "amazonaws.com", "cloudfront.net", "awsstatic.com",
	"cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com", "akamai.net", "akamaiedge.net", "akamaized.net", "akadns.net", "fastly.net", "fastlylb.net", "edgekey.net", "edgesuite.net",
	"github.com", "githubusercontent.com", "gitlab.com", "npmjs.org", "pypi.org", "docker.io", "docker.com", "ghcr.io",
	"letsencrypt.org", "digicert.com", "globalsign.com", "sectigo.com", "identrust.com", "godaddy.com",
	"ntp.org", "pool.ntp.org", "time.apple.com", "time.google.com", "time.windows.com", "time.cloudflare.com",
	"mozilla.org", "mozilla.net", "firefox.com",
	"whatsapp.net", "whatsapp.com", "signal.org", "telegram.org", "discord.com", "discordapp.com", "slack.com", "zoom.us",
	"paypal.com", "stripe.com", "visa.com", "mastercard.com",
	"netflix.com", "nflxvideo.net", "nflximg.net", "spotify.com", "scdn.co", "disneyplus.com", "hulu.com",
	"steampowered.com", "steamcontent.com", "playstation.net", "xboxlive.com", "nintendo.net",
	"tailscale.com", "tailscale.io", "wireguard.com", "openrouter.ai", "anthropic.com", "openai.com",
	"cooli.ai", "wakxi.com",
}

// Protected says whether an automated actor may block a domain, and why not.
// Operators can still block any of these by hand.
func Protected(domain string) (bool, string) {
	d := normalize(domain)
	if d == "" {
		return true, "not a valid domain"
	}
	if !strings.Contains(d, ".") || strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".lan") ||
		strings.HasSuffix(d, ".home.arpa") || strings.HasSuffix(d, ".internal") || strings.HasSuffix(d, ".arpa") {
		return true, "local or reverse name"
	}
	for _, p := range protectedDomains {
		if d == p || strings.HasSuffix(d, "."+p) {
			return true, "essential service (" + p + ")"
		}
	}
	if isInfrastructure(d) {
		return true, "infrastructure host (updates, certificates, time, push)"
	}
	if isLikelyCDN(d) {
		return true, "content delivery host shared by many sites"
	}
	if reg := registrable(d); reg == d && len(strings.Split(d, ".")) == 2 {
		// A bare registrable domain with a well-known TLD and a short label is
		// too likely a brand; the assessment can name the specific host.
		if len(strings.Split(d, ".")[0]) <= 4 {
			return true, "short second-level domain"
		}
	}
	return false, ""
}
