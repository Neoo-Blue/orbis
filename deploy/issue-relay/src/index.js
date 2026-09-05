// Orbis issue relay.
//
// A node POSTs a scrubbed report; the relay dedupes it against the board by
// fingerprint and either opens an issue or comments on the existing one. It
// holds the only GitHub token, applies a second pass of redaction (defence in
// depth: the node already scrubbed), caps volume per client and per day, and
// never stores the report anywhere but GitHub.

const MAX_TITLE = 200;
const MAX_BODY = 30_000;
const MAX_LABELS = 8;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, repo: env.REPO, usage: "POST /report" });
    }
    if (request.method !== "POST" || url.pathname !== "/report") {
      return json({ error: "POST /report" }, 404);
    }
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await allow(env, `ip:${ip}`, Number(env.MAX_PER_IP_PER_HOUR || 12), 3600))) {
      return json({ error: "too many reports from this address; try again later" }, 429);
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "body must be JSON" }, 400);
    }
    const repo = env.REPO;
    if (body.repo && body.repo !== repo) {
      return json({ error: `this relay files to ${repo} only` }, 400);
    }
    const fp = String(body.fingerprint || "").replace(/[^0-9a-f]/gi, "").slice(0, 32);
    if (fp.length < 8) return json({ error: "fingerprint is required" }, 400);
    const version = scrub(String(body.version || "dev")).slice(0, 40);
    const action = body.action === "comment" ? "comment" : "create";

    const gh = github(env.GITHUB_TOKEN);
    const existing = await findByFingerprint(gh, repo, fp);

    if (action === "comment") {
      if (!existing) return json({ error: "no issue with that fingerprint" }, 404);
      const text = scrub(String(body.body || "")).slice(0, 2000) ||
        `Seen again on Orbis ${version}.`;
      if (existing.state === "closed") {
        return json({ number: existing.number, url: existing.html_url, created: false, closed: true });
      }
      await gh(`/repos/${repo}/issues/${existing.number}/comments`, { body: text });
      return json({ number: existing.number, url: existing.html_url, created: false });
    }

    if (existing) {
      // Same problem, another node (or the same one after a reset): count
      // it on the existing issue instead of opening a duplicate.
      if (existing.state === "open") {
        const n = Number(body.occurrences || 1);
        await gh(`/repos/${repo}/issues/${existing.number}/comments`, {
          body: `Reported again from another Orbis node (version ${version}, ${n} occurrence${n === 1 ? "" : "s"} there).`,
        });
      }
      return json({ number: existing.number, url: existing.html_url, created: false, closed: existing.state === "closed" });
    }

    if (!(await allow(env, "day", Number(env.MAX_NEW_ISSUES_PER_DAY || 60), 86400))) {
      return json({ error: "the relay's daily cap on new issues is reached; try tomorrow" }, 429);
    }
    const title = scrub(String(body.title || "").trim()).slice(0, MAX_TITLE);
    if (!title) return json({ error: "title is required" }, 400);
    let text = scrub(String(body.body || "")).slice(0, MAX_BODY);
    if (!text.includes(`orbis-fp:${fp}`)) text = `<!-- orbis-fp:${fp} -->\n` + text;
    text += `\n\n_Filed through the Orbis issue relay._`;
    const labels = Array.isArray(body.labels)
      ? body.labels.map((l) => String(l).toLowerCase().replace(/[^a-z0-9:_.-]/g, "-").slice(0, 50)).filter(Boolean).slice(0, MAX_LABELS)
      : ["orbis-report"];
    if (!labels.includes("orbis-report")) labels.push("orbis-report");
    if (!labels.includes("relay")) labels.push("relay");

    const created = await gh(`/repos/${repo}/issues`, { title, body: text, labels });
    return json({ number: created.number, url: created.html_url, created: true });
  },
};

async function findByFingerprint(gh, repo, fp) {
  const q = encodeURIComponent(`repo:${repo} is:issue "orbis-fp:${fp}" in:body`);
  const res = await gh(`/search/issues?q=${q}&per_page=3`);
  const items = (res && res.items) || [];
  // Prefer an open issue; otherwise the most recent closed one.
  return items.find((i) => i.state === "open") || items[0] || null;
}

function github(token) {
  return async (path, payload) => {
    const res = await fetch(`https://api.github.com${path}`, {
      method: payload ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "orbis-issue-relay",
        ...(payload ? { "Content-Type": "application/json" } : {}),
      },
      body: payload ? JSON.stringify(payload) : undefined,
    });
    if (!res.ok) {
      const t = (await res.text()).slice(0, 300);
      throw new Error(`GitHub ${res.status}: ${t}`);
    }
    return res.json();
  };
}

// allow is a fixed-window counter in KV: cheap, good enough for abuse control.
async function allow(env, key, limit, windowSec) {
  const bucket = Math.floor(Date.now() / 1000 / windowSec);
  const k = `${key}:${bucket}`;
  const cur = Number((await env.LIMITS.get(k)) || 0);
  if (cur >= limit) return false;
  await env.LIMITS.put(k, String(cur + 1), { expirationTtl: windowSec + 60 });
  return true;
}

// scrub is the relay's own pass: the node already replaced identifiers, but a
// node running an older build, or a hand-written report, should not leak.
function scrub(s) {
  return s
    .replace(/\b(?:sk|tskey|ghp|gho|ghu|ghs|github_pat)[-_][A-Za-z0-9_-]{8,}\b/g, "[key]")
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[email]")
    .replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, "[mac]")
    .replace(/\b(?!(?:1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|127\.\d+\.\d+\.\d+|0\.0\.0\.0)\b)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g, "[ip]")
    .replace(/(^|[^0-9a-z:])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4})(?![0-9a-z:])/gi, (m, lead, body) =>
      /^\d{1,2}:\d{2}(:\d{2})?$/.test(body) || !/[a-f:]{2}/i.test(body) ? m : `${lead}[ip6]`);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
