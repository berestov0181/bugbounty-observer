import json, glob, socket
from datetime import datetime

CVE_INFO = {
    'CVE-2025-23419': ('nginx', 'nginx TLS session resumption bypass of client certificate authentication'),
    'CVE-2026-33523': ('Apache httpd', 'mod_proxy buffer overflow allowing remote code execution'),
    'CVE-2026-33006': ('Apache httpd', 'heap-based buffer overflow in mod_ssl'),
    'CVE-2026-34032': ('OpenSSL', 'NULL pointer dereference in X.509 certificate parsing'),
    'CVE-2026-24072': ('OpenSSL', 'use-after-free in SSL_free_buffers'),
    'CVE-2026-33857': ('Apache httpd', 'improper input validation in mod_rewrite'),
    'CVE-2026-34059': ('Apache httpd', 'HTTP request smuggling vulnerability'),
    'CVE-2026-29169': ('OpenSSL', 'timing side-channel in RSA decryption'),
    'CVE-2025-49812': ('Linux kernel', 'privilege escalation via io_uring subsystem'),
    'CVE-2025-59775': ('OpenSSH', 'remote code execution in sshd pre-authentication'),
    'CVE-2025-26465': ('OpenSSH', 'machine-in-the-middle in ssh client'),
    'CVE-2025-26466': ('OpenSSH', 'denial of service via memory exhaustion'),
    'CVE-2026-35385': ('Linux kernel', 'use-after-free in netfilter subsystem'),
    'CVE-2026-35388': ('Linux kernel', 'heap overflow in ext4 filesystem driver'),
    'CVE-2026-35414': ('Linux kernel', 'privilege escalation via dirty pipe variant'),
    'CVE-2025-32728': ('Linux kernel', 'out-of-bounds write in USB subsystem'),
    'CVE-2025-55753': ('Linux kernel', 'race condition in memory management subsystem'),
    'CVE-2026-33007': ('Apache httpd', 'server-side request forgery in mod_proxy'),
    'CVE-2026-23918': ('Apache httpd', 'integer overflow in request parsing'),
    'CVE-2025-6491':  ('PHP', 'remote code execution via deserialization'),
    'CVE-2025-1736':  ('PHP', 'SQL injection via crafted HTTP headers'),
    'CVE-2025-1220':  ('PHP', 'path traversal in file upload handling'),
}

def get_banner(ip, port, timeout=3):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080):
            s.send(b'HEAD / HTTP/1.0\r\nHost: x\r\n\r\n')
        b = s.recv(512).decode('utf-8','ignore').split('\n')[0].strip()
        s.close()
        return b
    except:
        return ''

all_hits = []
seen = set()
for f in glob.glob('data/global_companies/hits_*.json'):
    for h in json.load(open(f)):
        if h['domain'] not in seen:
            seen.add(h['domain'])
            all_hits.append(h)

vuln = [h for h in all_hits if h['vulns']]
fresh = [h for h in vuln if any('2025' in v or '2026' in v for v in h['vulns'])]
junk = {'share price','euro','indian economy','electronic trading'}
fresh = [h for h in fresh if h['company'].lower() not in junk]
print(f'Targets: {len(fresh)} | Grabbing banners...')

lines = [
    'GLOBAL DISCLOSURE REPORT — PROFESSIONAL EDITION',
    '=' * 60,
    'Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M UTC'),
    'Targets: ' + str(len(fresh)),
    '=' * 60, ''
]

for h in sorted(fresh, key=lambda x: x['country']):
    fc = [v for v in h['vulns'] if '2025' in v or '2026' in v]
    contact = h.get('contact', 'security@' + h['domain'])
    ip = h['ip']
    domain = h['domain']
    ports = h.get('ports', [])
    company = h['company']

    stacks = []
    vuln_details = []
    for cve in fc:
        stack, desc = CVE_INFO.get(cve, ('Unknown', 'security vulnerability'))
        if stack not in stacks:
            stacks.append(stack)
        vuln_details.append((cve, stack, desc))

    banner = ''
    for port in [443, 80, 8443, 8080]:
        if port in ports:
            banner = get_banner(ip, port)
            if banner:
                break

    lines += [
        'Company:  ' + company + ' — ' + h.get('country',''),
        'Domain:   ' + domain,
        'IP:       ' + ip,
        'Ports:    ' + str(ports[:8]),
        'Banner:   ' + (banner if banner else 'not retrieved'),
        'Stack:    ' + ', '.join(stacks),
        'Contact:  ' + contact,
        '',
        '--- DISCLOSURE LETTER ---',
        'To: ' + contact,
        'Subject: Responsible Disclosure: Security Vulnerabilities on ' + domain,
        '',
        'Hello ' + company + ' Security Team,',
        '',
        'My name is Andrey Berestov, independent security researcher.',
        'During routine open-source intelligence (OSINT) research, I identified',
        'potential security vulnerabilities in your infrastructure.',
        '',
        'AFFECTED HOST:',
        '  Host:    ' + domain,
        '  IP:      ' + ip,
        '  Ports:   ' + str(ports[:8]),
        '  Banner:  ' + (banner if banner else 'n/a'),
        '  Stack:   ' + ', '.join(stacks),
        '',
        'IDENTIFIED VULNERABILITIES:',
        '',
    ]

    for cve, stack, desc in vuln_details:
        lines += [
            '  [' + cve + '] ' + stack,
            '  ' + desc,
            '  https://nvd.nist.gov/vuln/detail/' + cve,
            '',
        ]

    lines += [
        'RECOMMENDED ACTIONS:',
        '  1. Verify ' + ', '.join(stacks) + ' version on ' + domain,
        '  2. Apply all vendor security patches immediately',
        '  3. Review access logs for signs of exploitation',
        '  4. Consider WAF rules as temporary mitigation',
        '',
        'DISCLOSURE TERMS:',
        '  - Submitted in good faith under responsible disclosure principles',
        '  - Requesting acknowledgment within 7 days',
        '  - 90-day remediation window before public disclosure',
        '  - No exploitation performed, no data accessed',
        '',
        'If you have a bug bounty program, I am happy to submit via your preferred channel.',
        '',
        'Best regards,',
        'Andrey Berestov',
        'Independent Security Researcher',
        'berestov0181@gmail.com',
        '-' * 60,
        '',
    ]

open('data/global_companies/global_disclosure_report.txt','w').write('\n'.join(lines))
print('[+] Saved: data/global_companies/global_disclosure_report.txt')
print('[+] Total lines: ' + str(len(lines)))
