# Privacy

## What is collected

From Windows: OS build/timezone, proxy settings (WinINET, WinHTTP, environment variables), hosts file
summary (hash + target overrides only), browser policy registry values, firewall profile state, firewall
rules filtered to Clash/browser executables (when permissions allow), installed network software,
TLS interception is *not* assessed automatically.

From Clash: config file list and SHA256, selected profile metadata, policy summary (mode, ports, DNS, TUN,
sniffer, rules, proxy groups, node fields), complete node SHA256 fingerprints, script files as fingerprints
only, GeoSite/GeoIP file hashes, 5-round connection probes (CONNECT/TLS/HTTP status and timing),
route checks and an egress IP echo (SHA256 + reported country).

## What is hashed or omitted

- UUIDs, passwords, tokens, private/public keys, short IDs, cookies, authorization values: **not exported**;
  only presence, length and SHA256.
- Node server addresses: exported only as SHA256 fingerprints.
- URL paths, query strings and fragments: omitted or replaced by a hash.
- Hosts file content: only a SHA256 and whether targeted domains are overridden.
- No account data, login sessions, browser history, cookies, or subscription URLs.

## What still needs care

Reports contain **machine-identifying network facts**: private IP addresses, default gateways, adapter
names, hostname/OS details, node names, ports, SNI values, config hashes and timings.

- Do not commit reports to a repository.
- Redact before sharing with anyone.
- An IPv4 address can be brute-forced from its SHA256, so a hashed IP is **not** anonymous.

## What the tools never do

- No write operations on network/Clash/browser/account state.
- No credential export.
- No privilege escalation, installers, or package downloads.
