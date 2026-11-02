# Claude Troubleshooting Checklist (with a read-only scanner)

A layered, self-service checklist that helps people figure out **where** a Claude access problem is happening:
region restriction, account state, network path, browser, or the desktop client.

> **Boundary**: this project does not provide — and must not be used for — ways to bypass any service's
> regional restrictions or access controls. Check the official list of supported countries first:
> https://support.claude.com/en/articles/8461763-where-can-i-access-claude
> If your actual location is not on the list, the answer is "not available there"; do not attempt to circumvent it.

## Contents

- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — 中文 version. The main deliverable: a fill-in checklist and an error-to-cause table.
- **scan/** (optional) — read-only Windows scripts. Run on a single machine; collects local network facts and
  Clash Verge / Mihomo policy facts into two JSON reports. It never modifies anything and never exports
  credentials in plain text.
- **docs/** — privacy, comparison methodology, known limitations.

## What the scanner does

- Reads the Clash Verge / Mihomo config directory, current profile, generated config, ordered rules,
  proxy groups and node fingerprints.
- Reads system proxy / WinHTTP / WinINET / environment proxies / hosts / browser policy registry /
  firewall profile state.
- Runs 5 rounds of CONNECT / TLS / HTTP probes plus an egress echo check.
- Writes windows-network.json and clash-policy.json.

## What it never does

- No changes to proxy, DNS, routes, firewall, Clash rules or nodes, browsers, or accounts.
- No account data, cookies, sessions, subscription URLs, or private keys.
- No privilege escalation, no installs.

## Report safety

Reports keep secrets hashed (length + SHA256) but still contain **private IPs, gateways, adapter names,
hostname, node name/port/SNI and config hashes**. Do not commit or publish them; redact before sharing.
Note that an IPv4 address can be brute-forced from its SHA256, so treat hashed IPs as sensitive.

## Requirements

Windows 10/11, PowerShell 5.1+, Python 3.9+ (PyYAML 6.0.3 is vendored, no pip needed).

## License

MIT. Vendored PyYAML 6.0.3 is MIT; see scan/vendor/PyYAML-LICENSE.txt.
