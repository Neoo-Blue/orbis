// Package ident turns the scraps a network device leaks — its MAC prefix,
// DHCP option ordering, User-Agent, and the hostnames it reaches for — into
// a vendor, an OS guess and a device class, so the client list reads like
// "Living Room Apple TV" instead of "a4:83:e7:11:22:33".
package ident

import (
	"strings"
)

// Vendor resolves the IEEE OUI (first three bytes of a MAC) to a
// manufacturer. The table covers the vendors that actually show up on a home
// or small-office network; anything unlisted returns "".
func Vendor(mac string) string {
	oui := normalizeOUI(mac)
	if oui == "" {
		return ""
	}
	if v, ok := ouiTable[oui]; ok {
		return v
	}
	return ""
}

func normalizeOUI(mac string) string {
	m := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(mac))
	if len(m) < 6 {
		return ""
	}
	return m[:6]
}

// IsRandomizedMAC reports whether the locally-administered bit is set, which
// modern phones use for per-network MAC rotation. Those devices need to be
// tracked by DHCP client-id or hostname instead, and the UI should say so
// rather than showing them as a new device every week.
func IsRandomizedMAC(mac string) bool {
	m := normalizeOUI(mac)
	if len(m) < 2 {
		return false
	}
	var b byte
	for i := 0; i < 2; i++ {
		c := m[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return false
		}
		b = b<<4 | v
	}
	return b&0x02 != 0
}

// DeviceClass guesses what kind of thing this is from vendor + hostname +
// the DHCP parameter-request fingerprint.
func DeviceClass(vendor, hostname, userAgent, dhcpFingerprint string) (class string, os string) {
	h := strings.ToLower(hostname)
	v := strings.ToLower(vendor)
	ua := strings.ToLower(userAgent)

	switch {
	case strings.Contains(ua, "iphone"):
		return "phone", "iOS"
	case strings.Contains(ua, "ipad"):
		return "tablet", "iPadOS"
	case strings.Contains(ua, "android"):
		return "phone", "Android"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		return "laptop", "macOS"
	case strings.Contains(ua, "windows nt"):
		return "desktop", "Windows"
	case strings.Contains(ua, "cros"):
		return "laptop", "ChromeOS"
	case strings.Contains(ua, "linux") && !strings.Contains(ua, "android"):
		return "desktop", "Linux"
	}

	for _, hint := range hostnameHints {
		for _, frag := range hint.fragments {
			if strings.Contains(h, frag) {
				return hint.class, hint.os
			}
		}
	}

	// DHCP option-55 fingerprints are stable per OS family and survive MAC
	// randomization, which UA sniffing does not.
	switch dhcpFingerprint {
	case "1,121,3,6,15,119,252":
		return "laptop", "macOS/iOS"
	case "1,3,6,15,31,33,43,44,46,47,119,121,249,252":
		return "desktop", "Windows"
	case "1,33,3,6,12,15,26,28,51,58,59,121":
		return "phone", "Android"
	case "1,3,6,12,15,17,23,28,29,31,33,40,41,42,119":
		return "iot", "Linux/embedded"
	}

	switch {
	case strings.Contains(v, "apple"):
		return "apple-device", "Apple"
	case strings.Contains(v, "samsung"):
		return "phone", "Android"
	case strings.Contains(v, "google") || strings.Contains(v, "nest"):
		return "iot", ""
	case strings.Contains(v, "amazon"):
		return "iot", "FireOS"
	case strings.Contains(v, "roku"):
		return "tv", "Roku OS"
	case strings.Contains(v, "sonos"):
		return "speaker", ""
	case strings.Contains(v, "ring") || strings.Contains(v, "wyze") || strings.Contains(v, "hikvision") || strings.Contains(v, "dahua") || strings.Contains(v, "ubiquiti"):
		return "camera", ""
	case strings.Contains(v, "espressif") || strings.Contains(v, "tuya") || strings.Contains(v, "shelly") || strings.Contains(v, "sonoff"):
		return "iot", ""
	case strings.Contains(v, "raspberry"):
		return "server", "Linux"
	case strings.Contains(v, "intel") || strings.Contains(v, "dell") || strings.Contains(v, "lenovo") || strings.Contains(v, "hewlett"):
		return "desktop", ""
	case strings.Contains(v, "sony") || strings.Contains(v, "nintendo") || strings.Contains(v, "microsoft"):
		return "console", ""
	}
	return "unknown", ""
}

type hostnameHint struct {
	fragments []string
	class     string
	os        string
}

var hostnameHints = []hostnameHint{
	{[]string{"iphone"}, "phone", "iOS"},
	{[]string{"ipad"}, "tablet", "iPadOS"},
	{[]string{"macbook", "imac", "mac-mini", "macmini", "mbp", "mba"}, "laptop", "macOS"},
	{[]string{"apple-tv", "appletv"}, "tv", "tvOS"},
	{[]string{"homepod"}, "speaker", "audioOS"},
	{[]string{"android", "galaxy", "pixel", "oneplus"}, "phone", "Android"},
	{[]string{"desktop-", "laptop-", "win-", "-pc"}, "desktop", "Windows"},
	{[]string{"chromecast", "googlehome", "google-home", "nest-"}, "iot", ""},
	{[]string{"echo-", "alexa", "fire-tv", "firetv", "kindle"}, "iot", "FireOS"},
	{[]string{"roku"}, "tv", "Roku OS"},
	{[]string{"shield"}, "tv", "Android TV"},
	{[]string{"playstation", "ps4", "ps5"}, "console", "PlayStation"},
	{[]string{"xbox"}, "console", "Xbox"},
	{[]string{"switch"}, "console", "Nintendo"},
	{[]string{"sonos"}, "speaker", ""},
	{[]string{"printer", "hpprinter", "epson", "brother", "canon"}, "printer", ""},
	{[]string{"camera", "cam-", "doorbell", "ring-"}, "camera", ""},
	{[]string{"thermostat", "ecobee", "sensor", "bulb", "plug", "switch-"}, "iot", ""},
	{[]string{"raspberry", "raspberrypi", "rpi"}, "server", "Linux"},
	{[]string{"nas", "synology", "truenas", "unraid", "qnap"}, "nas", "Linux"},
	{[]string{"proxmox", "pve", "esxi"}, "server", "Linux"},
}

// ouiTable covers the manufacturers responsible for the overwhelming
// majority of consumer and SMB endpoints. It is a prefix map, not the full
// 30k-entry IEEE registry: keeping it in-binary means device naming works on
// an air-gapped install, and the long tail is better served by the optional
// downloadable OUI file the settings page can import.
var ouiTable = map[string]string{
	// Apple
	"A483E7": "Apple", "F0989D": "Apple", "3C0754": "Apple", "AC87A3": "Apple",
	"D0E140": "Apple", "F86214": "Apple", "8C8590": "Apple", "9C207B": "Apple",
	"E0ACCB": "Apple", "DC2B2A": "Apple", "F0DBF8": "Apple", "84FCFE": "Apple",
	"B8E856": "Apple", "40B395": "Apple", "6C4008": "Apple", "C82A14": "Apple",
	"7CD1C3": "Apple", "18AF61": "Apple", "5CF938": "Apple", "8866A5": "Apple",
	// Samsung
	"5C0A5B": "Samsung", "8CF5A3": "Samsung", "F008F1": "Samsung", "C81EE7": "Samsung",
	"E8508B": "Samsung", "34145F": "Samsung", "78BDBC": "Samsung", "1C5A3E": "Samsung",
	// Google / Nest
	"F4F5D8": "Google", "3C5AB4": "Google", "A47733": "Google", "6466B3": "Google",
	"1CF29A": "Google", "F4F5E8": "Google", "18B430": "Nest Labs", "641666": "Nest Labs",
	// Amazon
	"F0272D": "Amazon", "44650D": "Amazon", "34D270": "Amazon", "FCA183": "Amazon",
	"68544C": "Amazon", "84D6D0": "Amazon", "50DCE7": "Amazon", "0C47C9": "Amazon",
	// Intel
	"3C9860": "Intel", "8C1645": "Intel", "94E6F7": "Intel", "A0A8CD": "Intel",
	"E4B318": "Intel", "7C7A91": "Intel", "44032C": "Intel", "0026C7": "Intel",
	// Espressif (ESP32/ESP8266 - the bulk of DIY IoT)
	"240AC4": "Espressif", "3C71BF": "Espressif", "807D3A": "Espressif",
	"A020A6": "Espressif", "24B2DE": "Espressif", "84F3EB": "Espressif",
	"C4DD57": "Espressif", "7CDFA1": "Espressif", "D8A01D": "Espressif",
	// Raspberry Pi
	"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
	"D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi",
	// Ubiquiti
	"788A20": "Ubiquiti", "FCECDA": "Ubiquiti", "24A43C": "Ubiquiti",
	"802AA8": "Ubiquiti", "687251": "Ubiquiti", "744D28": "Ubiquiti",
	"E063DA": "Ubiquiti", "F09FC2": "Ubiquiti", "DC9FDB": "Ubiquiti",
	// TP-Link
	"5C6300": "TP-Link", "50C7BF": "TP-Link", "B0BE76": "TP-Link", "A42BB0": "TP-Link",
	"1027F5": "TP-Link", "6CB158": "TP-Link", "C46E1F": "TP-Link",
	// Netgear / Linksys / Asus
	"A040A0": "Netgear", "9C3DCF": "Netgear", "204E7F": "Netgear",
	"C0563C": "Linksys", "48F8B3": "Linksys", "C8D719": "Linksys",
	"AC220B": "ASUS", "382C4A": "ASUS", "04D9F5": "ASUS", "1C872C": "ASUS",
	// Roku / Sonos / Vizio
	"B0A737": "Roku", "CC6DA0": "Roku", "D83134": "Roku", "8C4962": "Roku",
	"5CAAFD": "Sonos", "B8E937": "Sonos", "347E5C": "Sonos", "48A6B8": "Sonos",
	"002018": "Vizio", "C40415": "Vizio",
	// Sony / Nintendo / Microsoft
	"FCF152": "Sony", "3C0771": "Sony", "00041F": "Sony",
	"7CBB8A": "Nintendo", "98B6E9": "Nintendo", "0009BF": "Nintendo",
	"7C1E52": "Microsoft", "501AC5": "Microsoft", "C83F26": "Microsoft",
	// LG / TCL / Hisense
	"CC2D8C": "LG", "A816B2": "LG", "3410F0": "LG",
	"D0035E": "TCL", "1CBF60": "TCL", "8C79F5": "Hisense",
	// Cameras / smart home
	"9C8ECD": "Wyze", "2CAA8E": "Wyze", "A4DA22": "Ring", "54E019": "Ring",
	"E0B94D": "Hikvision", "4CBD8F": "Hikvision", "BCAD28": "Dahua",
	"D0736C": "Shelly", "3C6105": "Tuya", "10D561": "Tuya", "68572D": "Sonoff",
	"ECFABC": "Philips Hue", "001788": "Philips Hue",
	// Printers
	"3C2AF4": "Brother", "008077": "Brother", "AC162D": "HP", "3822E2": "HP",
	"D8FE8F": "HP", "00265A": "Epson", "445E96": "Epson", "18A905": "Canon",
	// Server / NAS / infra
	"0011322": "Synology", "0011321": "Synology", "001132": "Synology",
	"245EBE": "QNAP", "00089B": "QNAP",
	"0050569": "VMware", "005056": "VMware", "000C29": "VMware", "001C14": "VMware",
	"525400": "QEMU/KVM", "0A0027": "VirtualBox", "080027": "VirtualBox",
	"00155D": "Hyper-V", "BC2411": "Proxmox",
	// Networking silicon commonly seen on generic gear
	"001B21": "Intel", "000AF7": "Broadcom", "001018": "Broadcom",
	"D4CA6D": "Routerboard/MikroTik", "6C3B6B": "MikroTik", "4C5E0C": "MikroTik",
	"E48D8C": "MikroTik", "2CC81B": "MikroTik", "748114": "MikroTik",
	// Phones / misc
	"F8E71E": "Xiaomi", "64B473": "Xiaomi", "286C07": "Xiaomi", "7802F8": "Xiaomi",
	"00259E": "Huawei", "48DB50": "Huawei", "781DBA": "Huawei",
	"D46E0E": "OnePlus", "94652D": "OnePlus", "C0EEFB": "OnePlus",
	"00E04C": "Realtek", "525401": "Realtek",
}

// LookupCount is exposed so the settings page can show how many prefixes the
// built-in table carries versus an imported registry.
func LookupCount() int { return len(ouiTable) }

// Merge folds an imported OUI registry into the table at runtime.
func Merge(entries map[string]string) int {
	n := 0
	for k, v := range entries {
		key := normalizeOUI(k)
		if key == "" || v == "" {
			continue
		}
		if _, exists := ouiTable[key]; !exists {
			ouiTable[key] = v
			n++
		}
	}
	return n
}
