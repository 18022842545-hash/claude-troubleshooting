[CmdletBinding()]
param([string]$OutputPath = (Join-Path $PSScriptRoot 'windows-network.json'))

# Read-only network inventory. The only write is the requested JSON report.
# Does not modify proxy/DNS/routes/firewall/Clash or elevate privileges.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:ScanErrors = New-Object System.Collections.Generic.List[object]
function Read-Section([string]$Name, [scriptblock]$Action) {
    try { & $Action } catch {
        $script:ScanErrors.Add([ordered]@{ section=$Name; status='Unavailable'; error_type=$_.Exception.GetType().Name })
        return $null
    }
}
function Safe-Path([string]$Value) {
    if (-not $Value) { return $Value }
    if ($env:USERPROFILE) { return $Value.Replace($env:USERPROFILE, '%USERPROFILE%') }
    return $Value
}
function Safe-Endpoint([string]$Value) {
    if (-not $Value) { return $Value }
    # Export endpoint host/port only. Never export URL credentials, path, query or fragment.
    $parts = @()
    foreach ($part in ($Value -split ';')) {
        $part = $part.Trim()
        if (-not $part) { continue }
        $prefix = ''
        if ($part -match '^(https?|socks[45]?)=(.+)$') { $prefix=$Matches[1]+'='; $part=$Matches[2] }
        $uri = $null
        $candidate = $part
        if ($candidate -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $candidate='http://'+$candidate }
        if ([Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri) -and $uri.Host) {
            $hostPart = $uri.DnsSafeHost
            if ($hostPart -match ':' -and $hostPart -notmatch '^\[') { $hostPart='['+$hostPart+']' }
            $parts += $prefix + $uri.Scheme + '://' + $hostPart + ':' + $uri.Port
        } else { $parts += '[unparsed endpoint omitted]' }
    }
    return ($parts -join ';')
}
function Safe-Bypass([string]$Value) {
    if (-not $Value) { return $Value }
    $parts = foreach ($part in ($Value -split '[;,]')) {
        if ($part -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { Safe-Endpoint $part }
        elseif ($part -match '^[\w.*<>:\[\]/%-]+$') { $part } else { '[unparsed bypass omitted]' }
    }
    return ($parts -join ';')
}
function Registry-Proxy([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return [ordered]@{present=$false} }
    $v=Get-ItemProperty -LiteralPath $Path
    return [ordered]@{
        present=$true; enabled=$v.ProxyEnable; server=(Safe-Endpoint $v.ProxyServer)
        bypass=(Safe-Bypass $v.ProxyOverride); pac_present=([bool]$v.AutoConfigURL)
        pac_endpoint=(Safe-Endpoint $v.AutoConfigURL); auto_detect_registry_hint=$v.AutoDetect
        note='AutoDetect alone is not authoritative; connection-specific WinINET flags are reported separately.'
    }
}
function Read-Policy([string]$Path) {
    $result=[ordered]@{registry_path=$Path;present=(Test-Path -LiteralPath $Path)}
    if (-not $result.present) { return $result }
    $v=Get-ItemProperty -LiteralPath $Path
    foreach ($name in @('DnsOverHttpsMode','BuiltInDnsClientEnabled','QuicAllowed','ProxyMode')) {
        if ($v.PSObject.Properties.Name -contains $name) { $result[$name]=$v.$name }
    }
    foreach ($name in @('DnsOverHttpsTemplates','ProxyServer','ProxyPacUrl')) {
        if ($v.PSObject.Properties.Name -contains $name) {
            $result[$name]=@(($v.$name -split '\s+') | ForEach-Object { Safe-Endpoint $_ })
        }
    }
    if ($v.PSObject.Properties.Name -contains 'ProxyBypassList') { $result.ProxyBypassList=Safe-Bypass $v.ProxyBypassList }
    return $result
}

$report=[ordered]@{
    schema='clash-windows-network-readonly-v1'; scanned_at_utc=(Get-Date).ToUniversalTime().ToString('o')
    privacy=[ordered]@{ credentials_exported=$false; browser_history_cookies_sessions_read=$false; url_paths_queries_fragments_omitted=$true; user_profile_path_normalized=$true }
    limitations=@(
        'A network snapshot cannot guarantee Claude login or account eligibility.'
        'Browser user preferences, proxy extensions and effective policy precedence require a separate browser/UI check; they are not inferred from policy registry alone.'
        'No packet contents, credentials, cookies, stored sessions, subscription URLs or private keys are collected.'
        'Physical interfaces, gateways and routes are machine-specific observations, not settings to clone.'
        'Unavailable sections are listed explicitly; no privilege escalation is attempted.'
    )
}
$report.os=Read-Section 'os' {
    $os=Get-CimInstance Win32_OperatingSystem
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    [ordered]@{ caption=$os.Caption; version=$os.Version; build=$os.BuildNumber; last_boot=$os.LastBootUpTime.ToUniversalTime().ToString('o'); timezone=(Get-TimeZone).Id; administrator=([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) }
}
$report.processes=Read-Section 'processes' {
    @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(clash.*|verge-mihomo|mihomo|msedge|chrome|v2ray.*|xray|sing-box|openvpn|wireguard|tailscale.*|zerotier.*|radmin.*|sangfor.*)\.exe$' } | ForEach-Object {
        $version=$null
        if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) { $version=(Get-Item -LiteralPath $_.ExecutablePath).VersionInfo.FileVersion }
        [ordered]@{ name=$_.Name; pid=$_.ProcessId; parent_pid=$_.ParentProcessId; executable=(Safe-Path $_.ExecutablePath); file_version=$version }
    })
}
$report.services=Read-Section 'services' {
    @(Get-CimInstance Win32_Service | Where-Object { ($_.Name+' '+$_.DisplayName) -match 'clash|mihomo|wireguard|openvpn|tailscale|zerotier|radmin|sangfor|sing-box' } | Select-Object Name,DisplayName,State,StartMode,ProcessId)
}
$report.installed_network_software=Read-Section 'installed_network_software' {
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path -LiteralPath $root) {
            foreach ($entry in (Get-ChildItem -LiteralPath $root)) {
                $v=Get-ItemProperty -LiteralPath $entry.PSPath
                if ($v.DisplayName -match 'Clash|Microsoft Edge$|Google Chrome|WireGuard|OpenVPN|Tailscale|ZeroTier|Radmin VPN|Sangfor|EasyConnect') {
                    [ordered]@{name=$v.DisplayName;version=$v.DisplayVersion;install_location=(Safe-Path $v.InstallLocation)}
                }
            }
        }
    }
}
$report.clash_autostart=Read-Section 'clash_autostart' {
    $rows=@()
    foreach ($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path -LiteralPath $path) {
            $item=Get-ItemProperty -LiteralPath $path
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -match 'clash|verge') { $rows += [ordered]@{ registry_path=$path; entry=$property.Name; command_present=([bool]$property.Value) } }
            }
        }
    }
    $rows
}
$report.system_proxy=Read-Section 'system_proxy' { Registry-Proxy 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' }
$report.machine_proxy=Read-Section 'machine_proxy' { Registry-Proxy 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' }
$report.wininet_connection_flags=Read-Section 'wininet_connection_flags' {
    $path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
    if (Test-Path -LiteralPath $path) {
        $value=(Get-ItemProperty -LiteralPath $path).DefaultConnectionSettings
        if ($value -and $value.Length -ge 12) {
            $flags=[BitConverter]::ToUInt32($value,8)
            [ordered]@{ direct_enabled=(($flags -band 1)-ne 0); proxy_enabled=(($flags -band 2)-ne 0); pac_enabled=(($flags -band 4)-ne 0); auto_detect_enabled=(($flags -band 8)-ne 0) }
        }
    }
}
$report.winhttp=Read-Section 'winhttp' {
    # netsh's output is localised. Read structured default WinHTTP configuration instead.
    if (-not ('ClashAuditWinHttp' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public class ClashAuditWinHttp {
 [StructLayout(LayoutKind.Sequential)] public struct Info { public uint AccessType; public IntPtr Proxy; public IntPtr Bypass; }
 [DllImport("winhttp.dll", SetLastError=true)] public static extern bool WinHttpGetDefaultProxyConfiguration(out Info info);
 [DllImport("kernel32.dll")] public static extern IntPtr GlobalFree(IntPtr memory);
}
'@
    }
    $info=New-Object ClashAuditWinHttp+Info
    if (-not [ClashAuditWinHttp]::WinHttpGetDefaultProxyConfiguration([ref]$info)) { throw 'WinHttpDefaultProxyUnavailable' }
    try { [ordered]@{ access_type=$info.AccessType; access_type_note='1=no proxy, 3=named proxy'; proxy=(Safe-Endpoint ([Runtime.InteropServices.Marshal]::PtrToStringUni($info.Proxy))); bypass=(Safe-Bypass ([Runtime.InteropServices.Marshal]::PtrToStringUni($info.Bypass))) } }
    finally { if ($info.Proxy -ne [IntPtr]::Zero) { [void][ClashAuditWinHttp]::GlobalFree($info.Proxy) }; if ($info.Bypass -ne [IntPtr]::Zero) { [void][ClashAuditWinHttp]::GlobalFree($info.Bypass) } }
}
$report.environment=Read-Section 'environment' {
    $rows=@()
    foreach ($scope in @('Process','User','Machine')) {
        $entry=[ordered]@{scope=$scope}
        foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')) {
            $value=[Environment]::GetEnvironmentVariable($name,$scope)
            if ($name -eq 'NO_PROXY') { $entry[$name]=Safe-Bypass $value } else { $entry[$name]=Safe-Endpoint $value }
        }
        $rows+=$entry
    }
    $rows
}
$report.adapters=Read-Section 'adapters' { @(Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,ifIndex,Status,LinkSpeed,Virtual,HardwareInterface,DriverVersion) }
$report.ip_addresses=Read-Section 'ip_addresses' { @(Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,IPAddress,PrefixLength,AddressState,PrefixOrigin,SuffixOrigin,SkipAsSource) }
$report.interfaces=Read-Section 'interfaces' { @(Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,Dhcp,InterfaceMetric,NlMtu,AutomaticMetric,Forwarding) }
$report.dns_servers=Read-Section 'dns_servers' { @(Get-DnsClientServerAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses) }
$report.routes=Read-Section 'routes' { @(Get-NetRoute | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric,Protocol,PolicyStore) }
$report.proxy_listeners=Read-Section 'proxy_listeners' { @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in @(7890,7891,7892,7893,7897,7900,9090) } | Select-Object LocalAddress,LocalPort,OwningProcess) }
$report.nrpt=Read-Section 'nrpt' {
    $rules=@(Get-DnsClientNrptPolicy)
    [ordered]@{ count=$rules.Count; dnssec_required_count=@($rules | Where-Object DnsSecValidationRequired).Count; namespace_values_omitted=$true }
}
$report.windows_doh=Read-Section 'windows_doh' {
    if (-not (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) { return [ordered]@{status='CommandNotAvailable'} }
    @(Get-DnsClientDohServerAddress | ForEach-Object { [ordered]@{ server_address=$_.ServerAddress; endpoint=(Safe-Endpoint $_.DohTemplate); allow_fallback=$_.AllowFallbackToUdp; auto_upgrade=$_.AutoUpgrade } })
}
$report.firewall_profiles=Read-Section 'firewall_profiles' { @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) }
$report.firewall_app_rules=Read-Section 'firewall_app_rules' {
    foreach ($filter in (Get-NetFirewallApplicationFilter | Where-Object { $_.Program -match '(?i)(clash[^\\/]*|verge-mihomo|mihomo|msedge|chrome)\.exe$' })) {
        foreach ($rule in (Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $filter)) {
            [ordered]@{program=(Safe-Path $filter.Program);enabled=[string]$rule.Enabled;direction=[string]$rule.Direction;action=[string]$rule.Action;profile=[string]$rule.Profile;policy_store_source_type=[string]$rule.PolicyStoreSourceType}
        }
    }
}
$report.security_products=Read-Section 'security_products' {
    @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState)
}
$report.tls_interception=[ordered]@{status='NotAssessed';certificate_stores_exported=$false;note='Security-product inventory does not establish TLS interception. Source Codex should inspect certificate issuer on a fresh official-site connection and relevant local HTTPS scanning settings. Do not export or copy certificates/private keys.'}
$report.hosts=Read-Section 'hosts' {
    $path=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $targets=@('claude.ai','claude.com','anthropic.com','api.anthropic.com','claudeusercontent.com','chatgpt.com','openai.com','github.com','www.baidu.com')
    $lines=@(Get-Content -LiteralPath $path | ForEach-Object { ($_ -split '#',2)[0].Trim() } | Where-Object { $_ })
    $overrides=@()
    foreach ($line in $lines) {
        $fields=$line -split '\s+'
        if ($fields.Count -gt 1) {
            foreach ($domain in $fields[1..($fields.Count-1)]) {
                if ($targets -contains $domain.ToLowerInvariant()) { $overrides += [ordered]@{domain=$domain;address=$fields[0]} }
            }
        }
    }
    [ordered]@{sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; noncomment_line_count=$lines.Count; target_overrides=$overrides; other_entries_omitted=$true}
}
$report.browser_policies=Read-Section 'browser_policies' {
    foreach ($path in @('HKCU:\Software\Policies\Microsoft\Edge','HKLM:\Software\Policies\Microsoft\Edge','HKCU:\Software\Policies\Google\Chrome','HKLM:\Software\Policies\Google\Chrome')) { Read-Policy $path }
}
$report.browser_startup_flags=Read-Section 'browser_startup_flags' {
    foreach ($p in (Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('msedge.exe','chrome.exe') })) {
        $flags=@()
        # Emit only known network option names. Values are omitted except safe booleans.
        foreach ($match in [regex]::Matches([string]$p.CommandLine,'--(proxy-server|proxy-pac-url|proxy-bypass-list|no-proxy-server|disable-quic|enable-quic|dns-over-https-mode|dns-over-https-templates)(?:=([^\s]+))?')) {
            $name=$match.Groups[1].Value
            $flags += [ordered]@{ flag='--'+$name; has_value=$match.Groups[2].Success; value_omitted=$match.Groups[2].Success }
        }
        if ($flags.Count -gt 0) { [ordered]@{browser=$p.Name;pid=$p.ProcessId;flags=$flags} }
    }
}
$report.browser_user_preferences=[ordered]@{status='NotCollected';reason='Avoids reading user-profile JSON that may contain unrelated secrets. Ask the user/source Codex to inspect effective proxy, secure DNS, QUIC and active proxy extensions in browser settings without exporting cookies or sessions.'}
$report.errors=@($script:ScanErrors.ToArray())
$fullOutput=[IO.Path]::GetFullPath($OutputPath)
$parent=Split-Path -Parent $fullOutput
if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent) }
$report | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $fullOutput -Encoding UTF8
Write-Output ('Report: '+$fullOutput)
Write-Output ('Unavailable sections: '+$script:ScanErrors.Count)
