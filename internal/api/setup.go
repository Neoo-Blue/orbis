package api

import (
	"fmt"
	"net/http"
	"strings"
)

// mountPublicSetup registers the unauthenticated onboarding surface: the
// Apple configuration profile and a self-contained setup page a phone can
// reach without logging into the admin UI. Both sit outside /api on purpose,
// the same reasoning as the raw certificate download: a device being set up
// has no session to present, and the certificate is public.
func (s *Server) handleCAMobileConfig(w http.ResponseWriter, r *http.Request) {
	if s.app.CA == nil {
		http.Error(w, "no certificate authority", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="orbis-filter.mobileconfig"`)
	_, _ = w.Write(s.app.CA.MobileConfig())
}

// handleSetup serves a device-detecting install page. It is deliberately one
// static, dependency-free HTML document: it has to render on an old smart-TV
// browser and a locked-down phone alike, before any certificate is trusted.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ua := strings.ToLower(r.UserAgent())
	var platform, steps, primary string
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod"):
		platform = "iPhone / iPad"
		primary = `<a class="btn" href="/orbis-ca.mobileconfig">Install the profile</a>`
		steps = `<li>Tap <b>Install the profile</b> above. Safari will say a profile was downloaded.</li>
			<li>Open <b>Settings</b>. Near the top you will see <b>Profile Downloaded</b>. Tap it, then <b>Install</b> (top right), and enter your passcode.</li>
			<li>Go to <b>Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings</b> and turn on the switch for <b>Orbis Filter CA</b>. This step is required.</li>`
	case strings.Contains(ua, "mac os") || strings.Contains(ua, "macintosh"):
		platform = "Mac"
		primary = `<a class="btn" href="/orbis-ca.mobileconfig">Download the profile</a>`
		steps = `<li>Tap <b>Download the profile</b>. Open the downloaded <code>orbis-filter.mobileconfig</code>.</li>
			<li>Open <b>System Settings &rarr; General &rarr; Device Management</b>, select the Orbis Filter profile and <b>Install</b> it.</li>
			<li>Prefer a browser extension instead? <b>uBlock Origin</b> removes YouTube and web ads with no certificate at all.</li>`
	case strings.Contains(ua, "android"):
		platform = "Android"
		primary = `<a class="btn" href="/orbis-ca.crt">Download the certificate</a>`
		steps = `<li>Tap <b>Download the certificate</b>.</li>
			<li>Open <b>Settings &rarr; Security &rarr; Encryption &amp; credentials &rarr; Install a certificate &rarr; CA certificate</b>, and pick the downloaded file.</li>
			<li>Android apps ignore user certificates, so this covers browsers only. For the YouTube <i>app</i>, cast it to a TV (handled with no certificate) or use a patched client.</li>`
	case strings.Contains(ua, "windows"):
		platform = "Windows"
		primary = `<a class="btn" href="/orbis-ca.crt">Download the certificate</a>`
		steps = `<li>Tap <b>Download the certificate</b>, then right-click it and choose <b>Install Certificate</b>.</li>
			<li>Choose <b>Local Machine</b>, then <b>Place all certificates in the following store &rarr; Trusted Root Certification Authorities</b>.</li>
			<li>Prefer no certificate? <b>uBlock Origin</b> in your browser removes YouTube and web ads without one.</li>`
	default:
		platform = "This device"
		primary = `<a class="btn" href="/orbis-ca.crt">Download the certificate</a>`
		steps = `<li>Download the certificate and add it to your system's trusted roots.</li>
			<li>On a television, you do not need this at all: pair it on the YouTube page and the Lounge engine handles ads with no certificate.</li>`
	}

	fingerprint := ""
	if s.app.CA != nil {
		fingerprint = s.app.CA.Fingerprint()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, setupHTML, platform, primary, steps, fingerprint)
}

const setupHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Set up Orbis on this device</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0d10;color:#e8ebf0;font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:24px}
.wrap{max-width:560px;margin:0 auto}
h1{font-size:22px;margin:8px 0 2px}
.sub{color:#93a0b4;margin:0 0 22px}
.card{background:#14181d;border:1px solid #232a33;border-radius:14px;padding:20px;margin-bottom:16px}
.btn{display:block;text-align:center;background:#3b82f6;color:#fff;text-decoration:none;font-weight:600;padding:14px 18px;border-radius:11px;margin:4px 0 16px}
.btn:active{background:#2f6fd6}
ol{margin:0;padding-left:20px}
li{margin:0 0 10px}
code{background:#0b0d10;border:1px solid #232a33;border-radius:6px;padding:1px 6px;font-size:13px}
.fp{font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#6b7787;word-break:break-all;margin-top:6px}
.tag{display:inline-block;font-size:12px;color:#93a0b4;border:1px solid #232a33;border-radius:999px;padding:2px 10px;margin-bottom:14px}
b{color:#fff}
</style></head><body><div class="wrap">
<span class="tag">Orbis Filter</span>
<h1>Set up %s</h1>
<p class="sub">Trusting the Orbis certificate lets it remove ads inside pages and streams on this device. It is optional: your network already blocks ad and tracker domains without it.</p>
<div class="card">
%s
<ol>%s</ol>
</div>
<div class="card">
<b>Verify before you trust it.</b> The certificate's fingerprint should match this:
<div class="fp">%s</div>
</div>
</div></body></html>`
