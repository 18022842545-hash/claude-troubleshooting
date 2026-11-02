# Read-only scanner

This folder contains the optional evidence collector used by the checklist in the parent directory.

| File | Purpose |
|---|---|
| Run-ReadOnlyScan.ps1 | Orchestrator: runs the two collectors below into one output directory |
| Collect-WindowsNetwork.ps1 | Collects Windows network facts (adapters, routes, DNS, proxies, hosts, browser policy, firewall profile state) |
| collect_clash.py | Collects Clash Verge / Mihomo policy facts (profile, rules, groups, node fingerprints, DNS/TUN, probes, egress echo) |
| vendor/ | PyYAML 6.0.3, pure Python, MIT (see vendor/PyYAML-LICENSE.txt) |

## Requirements

Windows 10/11, PowerShell 5.1+, Python 3.9+. No pip install needed — PyYAML is vendored.

## Run

From this directory:

~~~powershell
.\Run-ReadOnlyScan.ps1
~~~

If Clash Verge uses a non-default config directory:

~~~powershell
.\Run-ReadOnlyScan.ps1 -ConfigRoot 'D:\path\to\your\clash-verge-config'
~~~

Run the two parts separately if needed:

~~~powershell
.\Collect-WindowsNetwork.ps1 -OutputPath '.\Scan\windows-network.json'
python -B .\collect_clash.py --output '.\Scan\clash-policy.json' --windows-report '.\Scan\windows-network.json'
~~~

## Outputs

- **windows-network.json** — OS, network, proxy, hosts, browser-policy and firewall-profile facts.
  Sections based on WMI/CIM may be reported as "Unavailable" in restricted execution contexts; that is recorded,
  not guessed.
- **clash-policy.json** — Clash config files (hashed), selected profile, policy summary, complete node
  fingerprints, 5-round CONNECT/TLS/HTTP probes and an egress echo check.

## What it does not do

- Writes nothing except the two report files.
- Does not modify proxy, DNS, routes, firewall, Clash rules/nodes, browsers or accounts.
- Does not export accounts, cookies, sessions, subscription URLs or private keys in plain text.
- Does not escalate privileges or install anything.
- Only reads the Clash controller over loopback HTTP or a local named pipe.

## Privacy

Read [../docs/PRIVACY.md](../docs/PRIVACY.md) before sharing reports. They still contain local network
information (private IPs, gateways, adapter names, hostname, node metadata) and must not be committed
or published.
