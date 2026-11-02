# Comparison methodology (optional, for the scanner)

The scanner is primarily a **single-machine evidence collector**. Running it on two machines is optional.
If you do compare machines, compare in layers — "the YAML files look the same" is not a conclusion.

## Three layers, three separate verdicts

1. **Saved policy** — the profile file and enhancement scripts (hashed, parsed fields).
2. **Generated policy** — what the client generated from settings + profile (Clash Verge writes an applied
   config containing DNS/TUN/rules after merging).
3. **Runtime behavior** — actual probes, egress echo, controller state when readable. Probe success is
   behavioral evidence, not proof of account/login success.

## What to compare

- selected profile, complete normalized node fingerprint(s), proxy groups and current selections
- complete ordered rules (order matters) and rule-provider hashes
- DNS settings (fake-ip range, upstreams, fallback filters, policy), TUN settings, sniffing
- system proxy / WinHTTP / environment / browser policy layer
- machine-bound values are allowed to differ (adapter names, interface indexes, local IPs, gateways,
  routes, firewall rules, ports if genuinely in use by something else)

## What may differ without meaning "different policy"

- File SHA256 differences caused by formatting, comments or line endings
- Machine-specific paths, adapter names and local IPs
- Randomized controller pipe names, secrets and process IDs

## Rules of thumb

- Use the same version of this toolkit on both machines.
- "Unavailable" means unknown, not equal. Record it as unknown.
- Network policy equality, connectivity health and account/login success are three separate results;
  none of them implies the others.
- Never copy machine-bound network parameters just to make two machines byte-identical.
