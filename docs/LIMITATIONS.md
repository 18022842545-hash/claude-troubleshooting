# Known limitations

- **WMI/CIM sections may be unavailable.** Under restricted execution contexts, adapter, route, DNS,
  process, service, firewall and security-product queries can be denied. Reports mark these as
  "Unavailable"; they are never filled with guesses.
- **The Clash controller may be unreadable.** When the core runs in Windows service mode, its named pipe
  may reject the current user's process. Runtime config/rules/connections are then unavailable; reports
  keep only file-level evidence.
- **Browser user preferences are not read.** Secure DNS, proxy extensions and launch flags are not
  extracted from profile files. Reports record the policy registry (often absent) and leave browser
  settings as "default/unknown"; verify them in the browser UI.
- **Firewall rules are summarized, not fully audited.** Full rule enumeration may require administrator
  rights. Global port blocks, WFP filters, NRPT and third-party TLS interception are out of scope.
- **No account or eligibility checks.** The tool never logs in and cannot verify region eligibility,
  account status, verification state or billing. Cloudflare challenge responses are not a login verdict.
- **A snapshot is not a guarantee.** Network behavior can change over time and varies per service route.
- **Windows-only for the system collector.** collect_clash.py can be useful elsewhere, but the Windows
  facts collector requires PowerShell on Windows.
- **Read-only by design.** This is not a backup, migration, or configuration editor.
