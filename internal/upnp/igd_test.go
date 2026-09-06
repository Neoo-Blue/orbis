package upnp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const descXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>eero</friendlyName><manufacturer>eero inc.</manufacturer><modelName>eero Pro</modelName>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
     <controlURL>/ctl/IPConn</controlURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`

func TestDescribeFindsNestedWANService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/igd.xml":
			w.Write([]byte(descXML))
		case r.URL.Path == "/ctl/IPConn":
			action := r.Header.Get("SOAPAction")
			switch {
			case strings.Contains(action, "GetExternalIPAddress"):
				w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`))
			case strings.Contains(action, "GetGenericPortMappingEntry"):
				body := make([]byte, 4096)
				n, _ := r.Body.Read(body)
				if strings.Contains(string(body[:n]), "<NewPortMappingIndex>0<") {
					w.Write([]byte(`<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse><NewRemoteHost></NewRemoteHost><NewExternalPort>32400</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>32400</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Plex</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`))
					return
				}
				w.WriteHeader(500)
				w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>713</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
			case strings.Contains(action, "AddPortMapping"):
				w.WriteHeader(500)
				w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
			default:
				w.WriteHeader(500)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	gw, err := describe(context.Background(), srv.URL+"/igd.xml")
	if err != nil {
		t.Fatal(err)
	}
	if gw.ServiceType != "urn:schemas-upnp-org:service:WANIPConnection:1" || !strings.HasSuffix(gw.ControlURL, "/ctl/IPConn") {
		t.Fatalf("service not resolved: %+v", gw)
	}
	if gw.Model != "eero Pro" {
		t.Errorf("model = %q", gw.Model)
	}
	ip, err := gw.ExternalIP(context.Background())
	if err != nil || ip != "203.0.113.9" {
		t.Errorf("external ip = %q, %v", ip, err)
	}
	maps, err := gw.Mappings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(maps) != 1 || maps[0].ExtPort != 32400 || maps[0].Host != "192.168.1.50" || maps[0].Proto != "tcp" || maps[0].Description != "Plex" {
		t.Errorf("mappings = %+v", maps)
	}
	err = gw.AddMapping(context.Background(), Mapping{ExtPort: 32400, Proto: "tcp", Host: "192.168.1.60", Port: 32400})
	if err == nil || !strings.Contains(err.Error(), "already has a different mapping") {
		t.Errorf("conflict should surface as a plain sentence: %v", err)
	}
}
