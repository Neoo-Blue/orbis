# Orbis over MCP

Orbis speaks the Model Context Protocol on stdin/stdout, so an assistant can
query the network and, when allowed, change it.

The tools are not a separate surface. They are the same catalogue the built-in
assistant uses, executed through the same backend, because two independently
maintained tool sets drift: the one used less gets stale descriptions, loses a
parameter, and eventually lies about what it does.

## Running it

```bash
orbisd -mcp -config /etc/orbis/orbis.yaml            # 10 read-only tools
orbisd -mcp -mcp-write -config /etc/orbis/orbis.yaml # 21 tools, 11 mutating
```

Write access is off by default. With it off the mutating tools are not offered
at all rather than offered and refused, which is the same choice the built-in
assistant makes: a model told it can do something and then blocked produces a
worse conversation than one that was never given the capability.

Logs go to stderr. Nothing else may write to stdout, which carries the JSON-RPC
stream.

## Claude Code

```json
{
  "mcpServers": {
    "orbis": {
      "command": "ssh",
      "args": ["root@192.168.50.221", "orbisd", "-mcp", "-config", "/etc/orbis/orbis.yaml"]
    }
  }
}
```

Run it over SSH rather than exposing a port: the tools read the whole DNS
history and device inventory, and the node already trusts an SSH session.

## Tools

Read: `get_network_summary`, `list_clients`, `list_connections`,
`top_destinations`, `dns_log`, `top_blocked_domains`, `list_events`,
`list_firewall_rules`, `system_status`, `list_ad_candidates`.

Write (with `-mcp-write`): `block_domain`, `allow_domain`, `add_firewall_rule`,
`set_rule_enabled`, `delete_firewall_rule`, `apply_firewall`,
`set_client_blocked`, `label_client`, `decide_ad_candidate`, `flush_dns_cache`,
`refresh_blocklists`. Every one is written to the audit log with the actor
`mcp`.

## One caveat the server states in its own instructions

A node that is not on the traffic path records only its own traffic and
broadcast noise. Flows will look sparse and every source will be the node
itself. That is a placement problem, not a quiet network, and the difference
matters before drawing any conclusion from the data.
