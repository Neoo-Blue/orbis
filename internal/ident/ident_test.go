package ident

import "testing"

func TestDeviceClassHypervisorVendor(t *testing.T) {
	for _, vendor := range []string{"Proxmox", "VMware", "XenSource", "Parallels"} {
		class, os := DeviceClass(vendor, "", "", "")
		if class != "server" || os != "" {
			t.Errorf("%s: got class=%q os=%q, want server with no OS", vendor, class, os)
		}
	}
}
