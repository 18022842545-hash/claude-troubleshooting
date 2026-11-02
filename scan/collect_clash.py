"""Read-only Clash comparison collector. Writes only its JSON report.
Requires Python 3.9+; bundled pure-Python PyYAML is used without installation.
Never exports original configurations, credentials, cookies, or response bodies.
"""
import argparse, datetime, hashlib, http.client, io, ipaddress, json, os
import re, socket, ssl, struct, subprocess, sys, threading, time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent / 'vendor'))
import yaml

SECRET = re.compile(r'(?i)(uuid|password|passwd|token|secret|private.?key|public.?key|short.?id|cookie|authorization|credential|psk|certificate|headers|authentication)')
TOP = set('mode mixed-port port socks-port redir-port tproxy-port allow-lan bind-address ipv6 log-level unified-delay tcp-concurrent find-process-mode interface-name routing-mark keep-alive-interval keep-alive-idle disable-keep-alive global-client-fingerprint geodata-mode geodata-loader geo-auto-update geo-update-interval dns tun sniffer profile rules sub-rules routing-rule'.split())
VERGE = set('enable_auto_launch enable_silent_start enable_system_proxy enable_tun_mode enable_service_mode verge_mixed_port verge_socks_port verge_socks_enabled verge_http_enabled verge_port proxy_host proxy_auto_config system_proxy_bypass use_default_bypass enable_bypass_check enable_proxy_guard proxy_guard_duration enable_builtin_enhanced enable_dns_settings dns_settings profile_dns_settings tun_stack clash_core'.split())
NODES = set('name type port tls network udp flow servername client-fingerprint skip-cert-verify alpn packet-encoding ip-version dialer-proxy tfo mptcp smux'.split())
TARGETS = ['claude.ai', 'api.anthropic.com', 'chatgpt.com']

def digest(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()

def private(value):
    return {'present': value is not None, 'length': len(str(value)) if value is not None else 0, 'sha256': digest(value)}

def clean(value, key=''):
    if SECRET.search(str(key)):
        return private(value)
    if isinstance(value, dict):
        return {str(k): clean(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v, key) for v in value]
    if isinstance(value, str):
        if '://' in value:
            try:
                u = urlsplit(value)
                host = u.hostname or ''
                endpoint = u.scheme + '://' + host + (':' + str(u.port) if u.port else '')
                # Preserve standard DNS endpoints; all other URL paths and suffixes are hashed.
                endpoint += u.path if u.path in ['', '/', '/dns-query', '/resolve', '/generate_204'] else '/[redacted-path]'
                return {'endpoint': endpoint, 'original_sha256': digest(value), 'suffix_present': bool(u.query or u.fragment or u.username)}
            except Exception:
                return private(value)
        return value.replace(os.environ.get('USERPROFILE', 'NO_USERPROFILE'), '%USERPROFILE%')
    return value if value is None or isinstance(value, (int, float, bool)) else str(value)

def file_info(path):
    try:
        s = path.stat()
        return {'path': clean(str(path)), 'bytes': s.st_size, 'modified': datetime.datetime.fromtimestamp(s.st_mtime).astimezone().isoformat(), 'sha256': digest(path.read_bytes())}
    except Exception as e:
        return {'path': clean(str(path)), 'unavailable': type(e).__name__}

def read_yaml(path):
    result = yaml.safe_load(path.read_text(encoding='utf-8-sig'))
    return result if isinstance(result, dict) else {}

def summarize_cfg(cfg):
    result = {k: clean(v, k) for k, v in cfg.items() if k in TOP}
    result['nodes'] = []
    for n in cfg.get('proxies', []) or []:
        if not isinstance(n, dict):
            continue
        row = {k: clean(v, k) for k, v in n.items() if k in NODES}
        row['server_fingerprint'] = private(n.get('server'))
        row['complete_node_sha256'] = digest(n)
        row['sensitive_fields'] = {k: private(v) for k, v in n.items() if SECRET.search(k)}
        if isinstance(n.get('reality-opts'), dict):
            row['reality-opts'] = {k: private(v) for k, v in n['reality-opts'].items()}
        row['other_options_sha256'] = digest({k: v for k, v in n.items() if k not in NODES})
        result['nodes'].append(row)
    result['proxy-groups'] = []
    for g in cfg.get('proxy-groups', []) or []:
        allowed = 'name type proxies use strategy interval lazy tolerance filter exclude-filter exclude-type disable-udp hidden include-all include-all-proxies include-all-providers expected-status'.split()
        row = {k: clean(g[k], k) for k in allowed if k in g}
        if 'url' in g:
            row['healthcheck_url'] = clean(g['url'])
        result['proxy-groups'].append(row)
    for field in ['proxy-providers', 'rule-providers']:
        result[field] = {}
        for name, entry in (cfg.get(field) or {}).items():
            result[field][name] = {k: clean(v, k) if k in ['type','behavior','format','interval','path'] else private(v) for k, v in entry.items()}
    if 'hosts' in cfg:
        result['hosts'] = {'count': len(cfg['hosts'] or {}), 'sha256': digest(cfg['hosts'])}
    result['unknown_fields'] = {k: private(v) for k, v in cfg.items() if k not in TOP | {'proxies','proxy-groups','proxy-providers','rule-providers','hosts'}}
    return result

def bounded(fn, seconds=8):
    result = {}; event = threading.Event()
    def run():
        try: result['value'] = fn()
        except Exception as e: result['error'] = type(e).__name__
        finally: event.set()
    threading.Thread(target=run, daemon=True).start()
    if not event.wait(seconds):
        raise TimeoutError('Local read timed out')
    if 'error' in result:
        raise RuntimeError(result['error'])
    return result.get('value')

class PipeSocket:
    def __init__(self, pipe): self.pipe = pipe
    def makefile(self, *a, **kw): return io.BufferedReader(self.pipe)

class Controller:
    def __init__(self, cfg):
        self.secret = str(cfg.get('secret', ''))
        self.pipe = None; self.address = None
        ps = "[IO.Directory]::GetFiles('\\\\.\\pipe\\') | Where-Object { $_ -match 'verge-mihomo-production' }"
        proc = subprocess.run(['powershell.exe', '-NoProfile', '-Command', ps], capture_output=True, text=True, timeout=8)
        names = proc.stdout.strip().splitlines()
        if len(names) == 1:
            self.pipe = names[0]
        elif len(names) > 1:
            raise RuntimeError('Multiple controllers; manual identification required')
        else:
            candidate = str(cfg.get('external-controller-pipe', ''))
            if candidate.startswith('\\\\.\\pipe\\') and re.search('clash|mihomo', candidate, re.I):
                self.pipe = candidate
            elif cfg.get('external-controller'):
                u = urlsplit('http://' + str(cfg['external-controller']))
                if u.hostname not in ['localhost','127.0.0.1','::1']:
                    raise RuntimeError('Only explicit loopback controllers may be read')
                self.address = (u.hostname, u.port)
            else: raise RuntimeError('No local controller')

    def get(self, route):
        def perform():
            if self.pipe:
                with open(self.pipe, 'r+b', buffering=0) as p:
                    p.write(('GET ' + route + ' HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ' + self.secret + '\r\nConnection: close\r\n\r\n').encode())
                    r = http.client.HTTPResponse(PipeSocket(p)); r.begin()
                    if r.status != 200: raise RuntimeError('Controller returned non-200')
                    return json.loads(r.read())
            c = http.client.HTTPConnection(*self.address, timeout=6)
            try:
                c.request('GET', route, headers={'Authorization': 'Bearer ' + self.secret})
                r = c.getresponse()
                if r.status != 200: raise RuntimeError('Controller returned non-200')
                return json.loads(r.read())
            finally: c.close()
        return bounded(perform)

def probe(host, port, controller, mode='proxy', exit_check=False):
    row = {'host': host, 'mode': mode}; start = time.monotonic(); s = None
    try:
        if mode == 'proxy':
            s = socket.create_connection(('127.0.0.1', port), timeout=10)
            s.sendall(f'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n'.encode())
            data = b''
            while b'\r\n\r\n' not in data:
                b = s.recv(1)
                if not b or len(data) > 32768: raise ConnectionError('Invalid CONNECT response')
                data += b
            row['connect_status'] = int(data.splitlines()[0].split()[1])
            if row['connect_status'] != 200: raise ConnectionError('CONNECT rejected')
        else: s = socket.create_connection((host, 443), timeout=10)
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        row['tls'] = s.version()
        local_port = s.getsockname()[1]
        if controller:
            try:
                rows = controller.get('/connections').get('connections', [])
                row['routes'] = [clean({'chains': c.get('chains'), 'rule': c.get('rule'), 'payload': c.get('rulePayload'), 'inbound': c.get('metadata', {}).get('type')}) for c in rows if c.get('metadata', {}).get('host') == host and str(c.get('metadata', {}).get('sourcePort')) == str(local_port)]
                row['route_association'] = 'target_host_and_probe_source_port'
            except Exception as e: row['routes_unavailable'] = type(e).__name__
        path = '/cdn-cgi/trace' if exit_check else '/'
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html,application/json\r\nConnection: close\r\n\r\n'.encode())
        r = http.client.HTTPResponse(s); r.begin()
        row['http_status'] = r.status
        row['cloudflare_challenge'] = r.getheader('cf-mitigated') == 'challenge'
        if exit_check and r.status == 200:
            values = dict(line.split('=',1) for line in r.read(8192).decode(errors='replace').splitlines() if '=' in line)
            if 'ip' in values:
                row['egress_ip_sha256'] = digest(str(ipaddress.ip_address(values['ip'])))
            row['reported_country'] = values.get('loc')
            row['caution'] = 'Echo endpoint egress only; compare route chain with Claude. Not account eligibility.'
    except Exception as e:
        row['error_type'] = type(e).__name__
    finally:
        if s: s.close()
    row['seconds'] = round(time.monotonic()-start, 3)
    return row

def dns_client(server, qtype):
    transaction = int.from_bytes(os.urandom(2), 'big')
    packet = struct.pack('!HHHHHH', transaction, 0x100, 1, 0, 0, 0) + b'\x06claude\x02ai\x00' + struct.pack('!HH', qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5); s.sendto(packet, (server,53)); data,_ = s.recvfrom(4096)
    tid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    if tid != transaction: raise ValueError('DNS transaction mismatch')
    return {'server': server, 'qtype': qtype, 'rcode': flags & 15, 'answer_count': an}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config-root'); parser.add_argument('--output', required=True)
    parser.add_argument('--windows-report', help='JSON from Collect-WindowsNetwork.ps1 to locate actual TUN DNS')
    parser.add_argument('--skip-probes', action='store_true')
    args = parser.parse_args()
    root = Path(args.config_root) if args.config_root else Path(os.environ['APPDATA']) / 'io.github.clash-verge-rev.clash-verge-rev'
    result = {'schema': 2, 'fingerprint_algorithm': 'SHA256(JSON ensure_ascii=False, sort_keys=True, default=str; default Python separators)', 'time': datetime.datetime.now().astimezone().isoformat(), 'config_root': clean(str(root)), 'read_only': True, 'node_identity_boundary': 'Fingerprints compare saved node fields. Runtime API does not expose credentials; actual runtime credential equality is not directly attested. Provider nodes are unverified unless cached file fingerprints are present.', 'limitations': ['No account/session/cookie inspection or login.', 'Script bodies, unknown fields and secrets are hashes only.', 'No firewall/filter-driver/certificate-store export; source Codex must review relevant conflicts separately.', 'A successful HTTP probe is not successful Claude login.'], 'files': {}, 'errors': {}}
    generated = {}; registry = {}
    for name in ['config.yaml','verge.yaml','profiles.yaml','clash-verge.yaml']:
        p = root / name
        result['files'][name] = file_info(p)
        try:
            cfg = read_yaml(p)
            if name == 'profiles.yaml': registry = cfg
            elif name == 'verge.yaml':
                result['verge'] = {k: clean(v,k) for k,v in cfg.items() if k in VERGE}
                result['verge_unknown_fields'] = {k: private(v) for k,v in cfg.items() if k not in VERGE}
            else: result[name] = summarize_cfg(cfg)
            if name == 'clash-verge.yaml': generated = cfg
        except Exception as e: result['errors'][name] = type(e).__name__
    current = next((p for p in registry.get('items', []) if p.get('uid') == registry.get('current')), {})
    result['selected_profile'] = {k: clean(current[k],k) for k in ['uid','name','type','file'] if k in current}
    result['profile_extension_refs'] = {k: clean(v,k) for k,v in (current.get('option') or {}).items() if k in ['merge','script','rules','proxies','groups']}
    files = {str(p.get('file')) for p in registry.get('items',[]) if p.get('uid') in set(result['profile_extension_refs'].values()) | {registry.get('current')} and p.get('file')}
    for uid, default in [('Merge','Merge.yaml'),('Script','Script.js')]:
        global_item = next((p for p in registry.get('items',[]) if p.get('uid') == uid), {})
        files.add(str(global_item.get('file') or default))
    for name in sorted(files):
        p = (root / 'profiles' / name).resolve()
        if (root / 'profiles').resolve() not in p.parents:
            result['errors'][name] = 'OutsideProfilesDirectory'; continue
        if not p.exists(): continue
        result['files']['profiles/' + name] = file_info(p)
        if p.suffix in ['.yaml','.yml']:
            try: result['files']['profiles/' + name]['policy'] = summarize_cfg(read_yaml(p))
            except Exception as e: result['errors'][name] = type(e).__name__
    result['geodata'] = [file_info(p) for p in root.iterdir() if p.is_file() and p.suffix.lower() in ['.dat','.mmdb','.metadb']]
    result['rule_provider_files'] = []
    for provider in (generated.get('rule-providers') or {}).values():
        if not provider.get('path'): continue
        p = (root / str(provider['path'])).resolve()
        if root.resolve() in p.parents: result['rule_provider_files'].append(file_info(p))
    result['proxy_provider_cache'] = []
    for name, provider in (generated.get('proxy-providers') or {}).items():
        row = {'name': name, 'node_identity': 'unverified'}
        if provider.get('path'):
            p = (root / str(provider['path'])).resolve()
            if root.resolve() in p.parents:
                row['file'] = file_info(p)
                try:
                    row['nodes'] = summarize_cfg(read_yaml(p))['nodes']
                    row['node_identity'] = 'cached_fields_fingerprinted_runtime_equality_unverified'
                except Exception as e: row['unavailable'] = type(e).__name__
        result['proxy_provider_cache'].append(row)
    ctrl = None; live = {}
    try:
        ctrl = Controller(generated)
        result['core_version'] = clean(ctrl.get('/version'))
        live = ctrl.get('/configs')
        result['runtime'] = {k: clean(v,k) for k,v in live.items() if k in TOP}
        result['runtime_rules'] = clean(ctrl.get('/rules'))
        proxies = ctrl.get('/proxies').get('proxies',{})
        result['runtime_groups'] = {n: {k: clean(p[k],k) for k in ['type','now','all','alive','udp','xudp','dialer-proxy'] if k in p} for n,p in proxies.items() if 'all' in p or n in ['DIRECT','REJECT']}
    except Exception as e: result['errors']['controller'] = type(e).__name__
    if not args.skip_probes:
        port = live.get('mixed-port') or generated.get('mixed-port')
        if isinstance(port, int) and port > 0:
            result['probes'] = []
            for rnd in range(1,6):
                for host in TARGETS:
                    row = probe(host,port,ctrl); row['round'] = rnd; result['probes'].append(row)
            result['route_checks'] = [probe(h,port,ctrl,m) for h,m in [('www.baidu.com','proxy'),('chat.deepseek.com','tun'),('claude.ai','tun'),('chatgpt.com','tun'),('github.com','proxy')]]
            result['egress_check'] = probe('www.cloudflare.com',port,ctrl,exit_check=True)
            checks = result['probes']
            result['stability'] = {'requests': len(checks), 'connect_200': sum(r.get('connect_status')==200 for r in checks), 'transport_errors': sum('error_type' in r for r in checks)}
        else: result['errors']['probes'] = 'MixedPortMissing'
        # Use this machine's observed adapter DNS. Never assume the reference gateway.
        tun = live.get('tun', {})
        if tun.get('enable') and args.windows_report:
            try:
                win = json.loads(Path(args.windows_report).read_text(encoding='utf-8-sig'))
                observed = {str(s) for r in win.get('dns_servers',[]) if str(r.get('InterfaceAlias','')).casefold() == str(tun.get('device','')).casefold() for s in r.get('ServerAddresses',[]) if ipaddress.ip_address(s).version == 4}
                if len(observed) != 1: raise ValueError('Unique actual TUN DNS not found')
                gateway = next(iter(observed))
                result['dns_client'] = [dns_client(gateway,t) for t in [1,28]]
                result['dns_client_note'] = 'DNS server read from observed Windows adapter matching the live TUN device.'
            except Exception as e: result['errors']['dns_client'] = type(e).__name__
        elif tun.get('enable'):
            result['dns_client_status'] = 'NotCollected: provide --windows-report to use actual adapter DNS'
    output = Path(args.output).resolve(); output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    print(json.dumps({'report': str(output), 'errors': result['errors'], 'stability': result.get('stability')},ensure_ascii=False))

if __name__ == '__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'fatal_error_type': type(e).__name__, 'note': 'No raw exception text printed to protect secrets.'})); sys.exit(1)
