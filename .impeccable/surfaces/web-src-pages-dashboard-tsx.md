---
version: 1
slug: "web-src-pages-dashboard-tsx"
primary_target: "web/src/pages/Dashboard.tsx"
related_targets: ["web/src/App.tsx","web/src/styles.css"]
---

# Orbis interface

Scope: the whole web interface, Simple and Advanced, with the Overview as first surface; plus the block page. Mode: Operate (the block page is a single Experience moment inside the same world).
Audience: the technical owner of a home network at a desk, then household members in Simple mode.
Job: answer "is my network safe?" first, then what Orbis stopped, what needs the owner, and let anything be explained and changed in seconds.
Constraints: no external requests at runtime, light on a Raspberry Pi, standard controls and navigation, 44px touch targets on mobile, reduced motion honoured, no em dashes in copy.
Memorable moment: the orbit chart, a real map of this network that is alive.

## Direction contract

THESIS: The network is a body with things in orbit around it, and Orbis draws it the way an observatory draws the sky. Refuses the category default of near-black panels, neon accent and a grid of stat cards.

OWN-WORLD: A star-atlas plate at night. Prussian-blue shell and tinted ground, pale brass hairlines for structure, jade for safe, vermilion only for a block or a threat, one reserved violet ink for a traced decision. Fine engraved rings and tick marks, no glow, no glass. One workhorse sans with tabular figures, a mono only for addresses, ports and hostnames.

STORY: The owner opens Orbis and reads one sentence: protected, or what is wrong. The chart shows every device and what it is doing right now. Anything vermilion can be opened and traced to the rule that decided it, and changed from there.

FIRST VIEWPORT: Standard left rail and top bar. Centre: the orbit chart filling the work area, Orbis at the centre, rings for LAN, gateway and internet, each device a body on its ring sized by traffic, live connections as thin arcs, blocked attempts flaring at the outer shield ring. Left of the chart, in the same plate: the state sentence at 28px and the count stopped today with its recent history. Right: a list of what needs the owner, then what was stopped. Below: top talkers and top blocked tables.

FORM: Star-atlas plate, candidate 4 of 7 on the ordered list. seed:a2bd5f00f4f0f33f
Raised from Midnight transit: every decision is drawn as one line through ordered stations, the deciding station marked, used by the block page and the trace views.
Raised from Orienteering map: one ink is reserved for the active trace and never used for anything else.
Raised from Developer console: destructive actions stand apart with deliberate space and stay outlined until focused.
Raised from Split-flap board: live values change in place and columns never move.
Signature interaction: hover or tap a body on the chart to light its orbit and its live arcs, click to open its drawer.
Motion grammar: slow continuous orbital drift on transform only, arcs travel once along their path, state changes settle in 200 ms with an exponential ease out; everything stops when the tab is hidden and under reduced motion.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
