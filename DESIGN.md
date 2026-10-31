---
name: Orbis
description: A home network drawn the way an observatory draws the sky.
colors:
  rail: "#003153"
  ground: "#041c2f"
  plate: "#06263e"
  raised: "#0a3150"
  raised-high: "#114169"
  hairline: "rgba(214, 190, 138, 0.25)"
  hairline-soft: "rgba(214, 190, 138, 0.13)"
  hairline-strong: "rgba(214, 190, 138, 0.46)"
  ivory: "#efe9da"
  text-dim: "#aab6c6"
  text-faint: "#93a4b8"
  jade: "#62d8b2"
  brass: "#d9bc7c"
  brass-light: "#e7cf97"
  brass-ink: "#1b1608"
  vermilion: "#f2643c"
  vermilion-ink: "#1d0a04"
  violet: "#b79cff"
  rose: "#e8a7c0"
  amber: "#f2b544"
  sky: "#8fb7ff"
typography:
  verdict:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "27px"
    fontWeight: 540
    lineHeight: 1.16
    letterSpacing: "-0.024em"
  figure:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "42px"
    fontWeight: 520
    lineHeight: 1
    letterSpacing: "-0.03em"
  stat:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "26px"
    fontWeight: 520
    lineHeight: 1.1
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "16px"
    fontWeight: 560
    lineHeight: 1.25
    letterSpacing: "-0.01em"
  card-title:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "13.5px"
    fontWeight: 560
    lineHeight: 1.25
    letterSpacing: "-0.012em"
  body:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
    fontFeature: "'tnum' 1"
  control:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.55
  label:
    fontFamily: "Geist Variable, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"
    fontSize: "12.5px"
    fontWeight: 500
    lineHeight: 1.5
  mono:
    fontFamily: "Geist Mono Variable, ui-monospace, SF Mono, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "'tnum' 1"
  block-headline:
    fontFamily: "Geist Mono, ui-monospace, SF Mono, Menlo, Consolas, monospace"
    fontSize: "46px"
    fontWeight: 500
    lineHeight: 1.12
    letterSpacing: "-0.02em"
rounded:
  tag: "5px"
  sm: "6px"
  md: "8px"
  lg: "12px"
  full: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "14px"
  lg: "20px"
components:
  button:
    backgroundColor: "transparent"
    textColor: "{colors.ivory}"
    typography: "{typography.control}"
    rounded: "{rounded.sm}"
    padding: "7px 13px"
  button-primary:
    backgroundColor: "{colors.brass}"
    textColor: "{colors.brass-ink}"
    typography: "{typography.control}"
    rounded: "{rounded.sm}"
    padding: "7px 13px"
  button-primary-hover:
    backgroundColor: "{colors.brass-light}"
    textColor: "{colors.brass-ink}"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.vermilion}"
    typography: "{typography.control}"
    rounded: "{rounded.sm}"
    padding: "7px 13px"
  button-danger-hover:
    backgroundColor: "{colors.vermilion}"
    textColor: "{colors.vermilion-ink}"
  input:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.ivory}"
    typography: "{typography.control}"
    rounded: "{rounded.sm}"
    padding: "7px 11px"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.text-dim}"
    rounded: "{rounded.sm}"
    padding: "7px 9px"
  nav-item-current:
    textColor: "{colors.brass}"
    rounded: "{rounded.sm}"
    padding: "7px 9px"
  card:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ivory}"
    rounded: "{rounded.md}"
    padding: "14px"
  tag:
    backgroundColor: "{colors.raised-high}"
    textColor: "{colors.text-dim}"
    rounded: "{rounded.tag}"
    padding: "1px 7px"
---

# Design System: Orbis

## Overview

**Creative North Star: "A Star-Atlas Plate at Night"**

Orbis draws the network as a body with things in orbit around it, the way an observatory draws the sky. The ground is true Prussian blue, structure is engraved in pale brass, and text is ivory. Ink colour carries meaning and is rationed: jade for safe and live, vermilion for a stop, violet for a traced decision.

Density is that of a working instrument. Body type is 14px, cards are compact, and figures use tabular numerals so a column of live values holds still. The first screen of the Overview is one engraved plate rather than a grid of cards. Depth comes from a step of tone and a hairline. Motion is slow and continuous on the chart, quick and settled on controls, and it stops the moment nobody is looking.

The world refuses the category default of near-black panels with a neon accent. It has no glass, no glow and no additive blending.

**Key Characteristics:**
- Prussian ground in four tonal steps, with brass hairlines instead of shadows for structure.
- Colour as a rationed ink, each hue holding one job.
- One workhorse sans, Geist, with a mono only for strings a machine reads.
- A decision is always one line through ordered stations.
- Live values change in place and columns never move.
- Everything drawn is real data from this network.

## Colors

A cool, saturated blue ground with warm brass and ivory on top, and a small set of inks that each mean one thing.

### Primary
- **True Prussian Rail** (#003153): the navigation rail and the phone tab bar, the most saturated surface in the system. Text tokens are tuned to stay legible on it.
- **Atlas Ground** (#041c2f): the page, the top bar, the globe stage and the block page. Also the browser theme colour on the block page.
- **Plate Blue** (#06263e): cards, the plate, drawers, dialogs and the orbit chart, whose lettering is knocked out of this colour.

### Secondary
- **Engraver's Brass** (#d9bc7c): the primary button, the focus ring, the current navigation item, the gateway and centre of the chart, and the Orbis mark on the shell and block page.
- **Brass Hairlines** (rgba 214, 190, 138 at 0.13, 0.25 and 0.46): all rules, borders and chart rings. Soft for card edges and dividers, regular for controls and floating panels, strong for emphasis on hover.
- **Pale Brass** (#e7cf97) is the hover state of the primary button. **Brass Ink** (#1b1608) is the text on brass.

### Tertiary
- **Observatory Jade** (#62d8b2): safe and live. The state rule under a healthy verdict, live badges, an allowed station, a lit orbit on the chart, the light that runs along a new connection. It is also the colour of links, progress and meter fills, and the default sparkline.
- **Vermilion** (#f2643c): something was stopped or something is wrong. Blocks, threats, failed states, marks on the shield, the deciding station, and the destructive control that would stop something. **Vermilion Ink** (#1d0a04) is the text on a filled destructive button.
- **Decision Violet** (#b79cff): the line and open stations of a traced decision, on the domain tester and the block page.
- **Rose** (#e8a7c0): what violet used to do elsewhere. Filtered traffic on the globe and tags, social traffic, music chips, and virtual hosts on the network map.
- **Signal Amber** (#f2b544): needs attention. Warnings, a paused device on the chart, the attention verdict.
- **Sky** (#8fb7ff): information and notices, the observe mode tag, tool names in the assistant, lookups on charts.

### Neutral
- **Raised** (#0a3150) and **Raised High** (#114169): inputs and banners sit one step up; tags, meter tracks and scrollbar thumbs sit two.
- **Ivory** (#efe9da): primary text and resting bodies on the chart.
- **Text Dim** (#aab6c6): secondary text and navigation labels.
- **Text Faint** (#93a4b8): table heads, captions and placeholders, kept at 4.6:1 on the rail.

### Named Rules
**The Reserved Ink Rule.** Violet is the traced decision and nothing else. If a surface is not showing how one decision was reached, it contains no violet.

**The Vermilion Rule.** Vermilion means something was stopped or something is wrong. It is never decoration, never a brand accent, and never a chart series for ordinary traffic.

**The Tinted State Rule.** A state chip is its ink as text, the same ink at about 8% as fill, and at about 25% as border. Solid fills are kept for the primary action and an armed destructive button.

## Typography

**Display Font:** Geist Variable (with the system sans stack)
**Body Font:** Geist Variable (with the system sans stack)
**Label/Mono Font:** Geist Mono Variable (with ui-monospace and SF Mono)

**Character:** One workhorse sans doing all the talking, in fine variable weights between the usual stops. The mono appears only where a character could be misread.

### Hierarchy
- **Verdict** (540, 27px, 1.16, tight tracking, 24px on phones): the one sentence that says whether the network is safe.
- **Figure** (520, 42px, 1): the count stopped today on the plate.
- **Stat** (520, 26px, 1.1, 24px on phones): secondary figures in stat cards.
- **Title** (560, 16px, 1.25): page titles in the top bar. Simple mode steps this to 17px.
- **Card title** (560, 13.5px, 1.25): headings on cards and the plate.
- **Body** (400, 14px, 1.55): default text, with tabular figures on across the whole app.
- **Control** (500, 13px): buttons, inputs and table cells.
- **Label** (500, 12.5px): field labels. Table heads and small meta sit at 12px. Everything is sentence case.
- **Mono** (400, 12.5px at most, down to 10.5px on the globe ticker): hostnames in lists and tables.
- **Block headline** (Geist Mono, 500, 1.12, clamp from 27px to 46px, 23px to 34px for long names): the hostname on the block page.

### Named Rules
**The Machine String Rule.** Geist Mono is for addresses, ports, hostnames and config keys, which include rule text, file names and model ids. Counts, rates and byte sizes stay in Geist with tabular figures.

**The Security Read Rule.** The block page headline is set in mono because that hostname is a security read: rn and m, l and 1 must stay distinct. This is the one headline in the system that is not Geist.

**The In-Place Rule.** Live values change in place. Tabular figures are on globally and columns never move, so a number updating is the only thing that happens.

## Layout

The app is a rail and a work area: a 224px navigation rail (208px in Simple mode), a 52px top bar, and a scrolling page with 20px padding. Cards sit in 12px to 14px gaps. Full-height views such as the globe and the assistant take the whole work area and manage their own scrolling.

The Overview's first screen is a single plate of three columns: state on the left (250px to 300px), the orbit chart in the middle, and what needs the owner and what was stopped on the right. Hairlines divide the columns. Stat cards and tables sit below the plate, not above it.

Below 1240px the right column folds under the plate. At 880px the rail collapses to a 60px icon rail, and on phones and in Simple mode it becomes a bottom tab bar with safe-area padding. Below 760px the plate stacks into one column with a square chart. Grids drop from four columns to two to one between 1180px and 600px. The block page keeps its text in a column up to 660px wide with the plate running behind it, and below 760px the plate becomes its own 128px strip above the text so no ring runs through the words.

**The One Plate Rule.** The first screen of the Overview is one engraved surface divided by hairlines, not a grid of cards.

**The Thumb Rule.** Controls are at least 44px tall on phones. Buttons, navigation items and segmented controls get this at 880px and below, and block page buttons have it everywhere.

## Elevation & Depth

The system is flat and tonal. Depth is a step up the ground ramp plus a hairline. Shadows exist only on things that truly float over other content, and they are dark and diffuse so they read as distance, never as light.

### Shadow Vocabulary
- **Float** (`box-shadow: 0 16px 40px -20px rgba(2, 8, 18, 0.9)`): tooltips, toasts, the confirm dialog, the globe detail panel and the command palette.
- **Drawer** (`box-shadow: -24px 0 60px -30px #000`): the side drawer.

### Named Rules
**The Step and Hairline Rule.** A surface separates from its parent by one tonal step and a hairline. Cards never carry a shadow.

**The No Light Rule.** Nothing emits light. No glass, no backdrop blur, no coloured shadow, no additive blending. All three.js materials use normal blending, and light on the chart is drawn as ink.

## Shapes

Corners are gently rounded and consistent: 8px for cards and panels, 6px for controls, 5px for tags, 12px for the chat composer and simple-mode icon wells. Full rounding is kept for pills, switches and dots.

The signature form is the engraved circle: fine concentric rings, dashed orbits at 2px on and 6px off, tick marks every 5 degrees with a longer one every sixth, and a faint fixed star field. The gateway is the one square on the chart, a 7px brass block, so it can never be mistaken for a device. Stations are 12px circles with a 2px ring. Verdict lines close with a 44px by 2px rule in the state's ink.

## Components

### Buttons
Quiet and outlined, with brass reserved for the one thing to do next.
- **Shape:** gently rounded (6px), 13px medium Geist, 7px by 13px padding.
- **Default:** transparent with a regular hairline and ivory text.
- **Primary:** solid brass with brass ink.
- **Hover / Focus:** default gains a brass border and a 9% brass tint; primary lightens to pale brass; every button presses down 1px. Focus is a 2px brass ring at 2px offset.
- **Danger:** vermilion text on a transparent ground with a 45% vermilion border. It fills solid vermilion only on hover or keyboard focus.

**The Held Fire Rule.** Destructive buttons stay outlined until hovered or focused. The confirm dialog uses this same button for its confirm action.

### Tags and Chips
- **Style:** 11.5px medium, 5px radius, tinted by the Tinted State Rule.
- **State:** allow and live in jade, block in vermilion, filtered in rose, warn in amber, info in sky, neutral on Raised High.
- **Small labels:** the status dots are 6px. Category and recommendation chips are the only uppercase in the design, at 10px to 10.5px with wide tracking.

### Cards / Containers
- **Corner Style:** 8px.
- **Background:** Plate Blue.
- **Shadow Strategy:** none, see Elevation & Depth.
- **Border:** one soft hairline. Card heads are divided from the body by another.
- **Internal Padding:** 14px, with heads at 11px by 14px.

### Inputs / Fields
- **Style:** Raised fill, regular hairline, 6px radius, 13px type, 7px by 11px padding. Textareas default to mono because they hold rules and config.
- **Focus:** the border turns brass with no extra ring.
- **Labels:** 12.5px dim labels above, 12px faint hints below.

### Navigation
- **Rail:** True Prussian with a soft hairline edge, group names in faint 12px, items in 13.5px dim text with a 15px stroke icon.
- **States:** hover adds an 8% brass tint and ivory text. The current item has a 15% brass tint, brass text and a 520 weight.
- **Mobile:** a bottom tab bar of icon above label, with an All pages sheet of tiles.
- **Segmented control:** a hairline-bordered strip whose pressed option takes the same brass tint, scrolling sideways on phones.

### Tables and Rows
Dense and legible at 13px. Heads are sticky, 12px faint text on the plate. Rows divide by soft hairlines and carry a hover tint and nothing else. Numeric columns are right aligned.

### Orbit Chart
The memorable moment and the home of the world. Orbis sits at the centre with a brass dot. Things that stay put are on the inner orbit and things people carry are on the outer, each sized by current traffic and drifting slowly. Each talking device has one line to the brass gateway on the shield, and traffic runs round the rim in one trunk per 30 degrees of longitude, thickening with bytes. A stopped lookup travels out in vermilion, flares once on the shield, and leaves a mark that stays for 15 seconds and can be opened. Hover or tap lights a device's orbit and lines in jade, and a click or second tap opens it. It draws to a canvas from refs, so a busy network costs a frame and never a React render.

### Decision Trace
Used on the domain tester and the block page. An ordered list of stations joined by one 2px line in Decision Violet. A block station fills vermilion and an allow station fills jade. On the block page the deciding station flares, and stations past it turn faint with a dotted line, because the request never reached them.

**The One Line Rule.** A decision is one line through ordered stations, in order, with the deciding station marked. It is never a table of checks or a stack of cards.

### Block Page
A single moment inside the same world, seen by anyone on the network. The hostname leads in mono, the plate shows this one request leaving the device and dying at the shield, and the trace explains why. Nothing on it is invented traffic. Its fonts and styles are served by the node itself. Buttons are 44px tall at every width.

**The Still Sky Rule.** Motion is transform and opacity on drift, a single pass along a path, and quick settling on state changes. The chart, the globe and the block page all stop their loops when the tab is hidden, and under reduced motion they stop moving and draw still. The orbit chart also pauses when it is scrolled off screen.

## Do's and Don'ts

### Do:
- **Do** use the true Prussian ramp, rail #003153, ground #041c2f and plate #06263e, for every surface.
- **Do** rule structure with brass hairlines and separate surfaces with one tonal step.
- **Do** keep jade for safe and live, and vermilion for a stop or a fault.
- **Do** use rose where a category needs a fourth hue. Violet is never the spare.
- **Do** set hostnames, addresses, ports and config keys in Geist Mono, and everything else in Geist.
- **Do** draw any decision as one line through ordered stations with the deciding station marked.
- **Do** update live values in place with tabular figures.
- **Do** treat the shield flare and the plate-coloured halo behind chart lettering as ink. They are strokes, not glow.
- **Do** stop every animation loop when the tab is hidden and draw a still frame under reduced motion.
- **Do** give controls a 44px minimum height on phones.

### Don't:
- **Don't** use violet for anything but a traced decision: not selection, not a chart series, not a badge.
- **Don't** use vermilion for ordinary traffic, decoration or emphasis.
- **Don't** use backdrop blur, glass panels, coloured shadows or additive blending.
- **Don't** put a shadow on a card. Shadows are for things that float.
- **Don't** fill a destructive button at rest.
- **Don't** set counts, rates or byte sizes in mono.
- **Don't** show traffic that is not real, on the chart or the block page.
- **Don't** use a loop that keeps running on a hidden tab. The node is a Raspberry Pi.
- **Don't** let a live update move a column or reflow a row.
