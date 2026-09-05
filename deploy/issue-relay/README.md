# Orbis issue relay

A tiny Cloudflare Worker that lets any Orbis node file a scrubbed problem
report on the project's GitHub issue board without holding a GitHub token.

- `POST /report` with the payload Orbis sends (`fingerprint`, `title`, `body`,
  `labels`, `severity`, `category`, `version`, `occurrences`, and `action`
  `create` or `comment` with `number`).
- Dedupes by fingerprint: the same problem from many nodes is one issue with
  "reported again" comments, not a pile of duplicates.
- Second-pass redaction of addresses, MACs, keys and email addresses.
- Per-address and per-day caps in KV.

Deploy:

```sh
wrangler kv namespace create LIMITS          # paste the id into wrangler.jsonc
gh auth token | wrangler secret put GITHUB_TOKEN
wrangler deploy
```

Then set `issues.github.relay_url` on a node to `https://<worker>/report`.
