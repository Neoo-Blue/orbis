# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: a technical owner running their own network from a homelab, on a Raspberry Pi, LXC, VM or Docker. They know what a resolver, a VLAN and a flow are, want full detail and fast control, and open Orbis at a desk, usually to check things are fine or to find out why something broke. Secondary: other people in the household, who use Simple mode, often on a phone.

## Product Purpose

Orbis is one static binary that is a filtering resolver, a firewall, three ad-removal engines, intrusion detection, threat intelligence, country rules, its own Wi-Fi network, a map of everything hosted on the LAN, and an assistant that can operate all of it. It exists so one owner can see and control a whole network without vendor hardware or subscriptions. Success is the owner trusting at a glance that the network is safe, and being able to explain and change anything Orbis did within seconds.

## Positioning

Orbis follows the ad into the stream and says, per device, which tool applies and what it cannot reach. It needs no managed switches, access points, cloud account or licence, unlike UniFi and Meraki, and its assistant takes audited, undoable actions on the live network.

## Operating Context

Runs on modest hardware: the reference node is a Raspberry Pi 4 with an SD card, reached over plain HTTP on the LAN or through a Cloudflare tunnel. The interface is embedded in the binary. Every page is polled or streamed from that node, so the UI must stay light on it. The block page is seen by anyone on the network, in a browser, at the moment a site fails to load.

## Capabilities and Constraints

Pages: Overview, Globe, Flows, Clients, DNS, Ad block, Firewall, Threats, Events, Analytics, Reports, Topology, Hosted apps, Services, VPN, Wi-Fi, Assistant, YouTube, Settings and more. Two interfaces, Simple and Advanced, both stay. React 18 and three.js, no component library, no external requests at runtime. Editing a TLS stream needs the device to trust the Orbis CA, so an HTTPS block page only renders on devices that trust it.

## Brand Commitments

The name Orbis and its orbit mark stay. Copy is plain and specific, says what happened and what to do next, and never uses em dashes. The owner wants the product elegant and trustworthy, never cartoonish or illustrated, with rich motion, and wants it to read as the best router and cybersecurity application there is. Interactive targets are at least 44px on mobile.

## Evidence on Hand

Live node data: about 72k DNS queries a day, 4.2M list entries, 57 known devices, 53 lists. Screenshots for public use must show demo data, never the owner's real devices or history. There are no customer testimonials or third-party benchmarks; do not invent any.

## Product Principles

- Say what is true: per device, what is protected, what is not, and why.
- Every verdict can be explained: anything blocked or allowed can be traced to the rule that decided it, and changed from there.
- The owner stays in charge: automatic actions are visible, audited and undoable.
- It runs on a Pi: nothing in the interface may make the node slower.
