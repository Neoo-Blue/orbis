# UX audit, 2026-09-05

Scope: every page of the web interface as shipped in 1.18, judged against one
question: could a person with no networking background operate every feature?
Findings are grouped by what was done about them.

## Fixed in this pass

- **Blank labels on the overview.** `.truncate` forced `max-width: 1px` on every
  element, a table-cell ellipsis trick that also collapsed device names, blocked
  domains and event titles in flex rows. Split into a flex-safe rule and a
  `td.truncate` rule.
- **Deploys under an open tab looked like bugs.** Stale styles and API shapes
  persisted until a manual reload. The app now compares the daemon's version on
  every status poll and offers a reload.
- **Inline mode silently reverted.** The API accepted inline without the
  firewall on, a WAN interface, or a zone, and the daemon fell back to observe
  at its next start. The update is now refused with the reason, and the page
  lists what is missing.
- **No way to express "this device is not filtered".** Added unfiltered
  policies (the AdGuard Home "filtering disabled" client).
- **No policy editor.** Policies existed only through the API and the client
  drawer's selector. Added a Profiles page with presets (Kids, Homework,
  Guests, Unfiltered), a full editor, and per-profile usage counts.
- **No timed block.** "Block device" was forever. Added pause with a timer
  (30 min, 1 h, 3 h, until resumed) lifted by the daemon.
- **No one-glance answer to "is everything OK".** Added `/api/health` and the
  simple home hero: a level, a sentence, and the reasons.
- **Two modes.** A simple interface (Home, Devices, Protection, Usage,
  Assistant, Alerts, Settings) in plain language with large targets and a
  bottom tab bar on phones, and the advanced interface with every page. The
  toggle sits in the top bar; the default is a setting.

## Findings carried as backlog

- **Terminology on advanced pages** assumes the vocabulary of a network
  engineer: SNI, QUIC, conntrack, nftables, DoH, ARP. Acceptable in advanced
  mode; tooltips with one-line definitions would still help.
- **Settings is 1,800 lines and 14 sections** with no search. A settings
  search (the command palette already indexes pages, not settings) is the
  obvious next step.
- **Onboarding** offers Simple and Advanced but only changes which wizard
  steps show; it should also set `node.ui_mode`.
- **Mobile** (fixed 2026-09-05, verified with phone-size screenshots of every
  page on a scratch instance). The simple tab bar had stacked vertically because
  the nav wraps items in a section div; the top bar squeezed the mode toggle to
  a sliver; Settings kept its 218 px side column; stat grids stayed two columns
  from an unlayered desktop rule; tab strips wrapped their labels; drawers were
  wider than the screen. All addressed. The advanced icon rail now has tooltips.
  Tables still scroll horizontally by design.
  Second pass, same day, for the advanced interface on phones: a five-slot
  bottom bar (Overview, Connections, Devices, Assistant, More) with an
  all-pages sheet behind More and a search button in the top bar; Devices
  renders as cards; pages stack their sections in inline grids whose single
  auto column grew to the widest unwrapped tab strip and stretched every
  banner and card past the screen, fixed with one rule that pins that column
  to the available width; Settings chips were inheriting the tab-bar rules;
  the Assistant composer and Globe controls were pushed below the fold by
  banners above a full-height view; the Globe legend collided with its view
  controls. Verified on every route with iPhone-size screenshots.
- **Empty states** vary in tone. Some explain what to do next, some do not.
- **Destructive actions** use `confirm()`; a consistent in-app confirmation
  with an undo toast would be better, particularly for block and delete.
- **Accessibility.** Colour carries meaning in several places (verdict dots,
  category pills) without a text equivalent; contrast on `--text-faint` is
  below AA on the darkest background.
- **Assistant as the universal control.** In simple mode the assistant is the
  most capable surface for non-technical users; the prompt is tuned for it,
  but write access defaults to off, so most "do X" requests turn into
  instructions. A guided "let the assistant make changes" step with a clear
  explanation of scope belongs in the simple settings.
