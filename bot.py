import os
import time
import sys
import json
import random
import warnings
from datetime import datetime, timezone
import pytz 
from colorama import Fore, Style, init
from curl_cffi import requests
from eth_account import Account
from eth_account.messages import encode_defunct

os.system('clear' if os.name == 'posix' else 'cls')
warnings.filterwarnings('ignore')
if not sys.warnoptions:
    os.environ["PYTHONWARNINGS"] = "ignore"
init(autoreset=True)

class AixCryptoBot:
    def __init__(self):
        self.sitekey = "0x4AAAAAAAM8ceq5KhP1uJBt"
        self.page_url = "https://hub.aixcrypto.ai/"
        self.privy_app_id = "cmk3zw8d704bxl70chtewm6hd"
        self.api_key_2captcha = ""
        self.api_key_sctg = ""
        self.accounts = []
        self.proxies = []
        self.max_bets = 5 
        self.use_proxy = False
        self.solver_type = "2captcha"
        self.market_history = [] 

    def get_wib_time(self):
        try:
            wib = pytz.timezone('Asia/Jakarta')
            return datetime.now(wib).strftime('%H:%M:%S')
        except:
            return datetime.now().strftime('%H:%M:%S')
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}AIXCRYPTO AUTO BOT{Style.RESET_ALL}
{Fore.WHITE}By: FEBRIYAN{Style.RESET_ALL}
{Fore.CYAN}============================================================{Style.RESET_ALL}
"""
        print(banner)
    
    def log(self, message, level="INFO"):
        time_str = self.get_wib_time()
        colors = {
            "INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "ERROR": Fore.RED,
            "WARNING": Fore.YELLOW, "BET": Fore.BLUE, "CYCLE": Fore.MAGENTA,
            "TASK": Fore.MAGENTA, "WIN": Fore.GREEN, "LOSE": Fore.RED,
            "AI": Fore.LIGHTMAGENTA_EX
        }
        color = colors.get(level, Fore.WHITE)
        print(f"[{time_str}] {color}[{level}] {message}{Style.RESET_ALL}")
    
    def format_proxy(self, proxy_str):
        if not proxy_str: return None
        if proxy_str.startswith("http") or proxy_str.startswith("socks"): return proxy_str
        parts = proxy_str.split(':')
        if len(parts) == 4: 
            return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        return f"http://{proxy_str}"

    def load_files(self):
        try:
            if os.path.exists("2captcha.txt"):
                with open("2captcha.txt", "r") as f: self.api_key_2captcha = f.read().strip()
            if os.path.exists("sctg.txt"):
                with open("sctg.txt", "r") as f: self.api_key_sctg = f.read().strip()
            with open("accounts.txt", "r") as f:
                self.accounts = [line.strip() for line in f if line.strip()]
            if os.path.exists("proxy.txt"):
                with open("proxy.txt", "r") as f:
                    raw_proxies = [line.strip() for line in f if line.strip()]
                    self.proxies = [self.format_proxy(p) for p in raw_proxies]
        except Exception as e:
            self.log(f"File missing: {e}", "ERROR")
            sys.exit()

    def show_menu(self):
        print(f"{Fore.CYAN}============================================================{Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN}Select Proxy Mode (1. Proxy / 2. No Proxy): {Style.RESET_ALL}").strip()
        self.use_proxy = True if choice == '1' else False
        solver_choice = input(f"{Fore.GREEN}Select Solver (1. 2Captcha / 2. SCTG): {Style.RESET_ALL}").strip()
        self.solver_type = "sctg" if solver_choice == '2' else "2captcha"
        input_bet = input(f"{Fore.GREEN}Enter Max Bets per Account : {Style.RESET_ALL}").strip()
        self.max_bets = int(input_bet) if input_bet else 5

    def solve_turnstile(self):
        import requests as r_sync
        self.log(f"Solving Captcha with {self.solver_type.upper()}...", "INFO")
        try:
            if self.solver_type == "2captcha":
                payload = {"key": self.api_key_2captcha, "method": "turnstile", "sitekey": self.sitekey, "pageurl": self.page_url, "json": 1}
                resp = r_sync.post("http://2captcha.com/in.php", data=payload).json()
                if resp.get('status') != 1: return None
                req_id = resp.get('request')
                for _ in range(30):
                    time.sleep(5)
                    res = r_sync.get(f"http://2captcha.com/res.php?key={self.api_key_2captcha}&action=get&id={req_id}&json=1").json()
                    if res.get('status') == 1: return res.get('request')
            else: # SCTG Logic
                from urllib.parse import urlencode
                params = {"key": self.api_key_sctg, "method": "turnstile", "pageurl": self.page_url, "sitekey": self.sitekey}
                response = r_sync.get("https://sctg.xyz/in.php?" + urlencode(params), timeout=30)
                if "|" in response.text:
                    task_id = response.text.split("|")[1]
                    for _ in range(60):
                        time.sleep(5)
                        poll = r_sync.get(f"https://sctg.xyz/res.php?key={self.api_key_sctg}&id={task_id}&action=get")
                        if "OK|" in poll.text: return poll.text.split("|")[1]
        except: return None
        return None

    def fetch_market_history(self, session, address):
        self.log("AI: Analyzing market history...", "INFO")
        try:
            url = f"https://hub.aixcrypto.ai/api/game/bet-history?address={address}&page=1&pageSize=10"
            resp = session.get(url).json()
            history = []
            for bet in resp.get("list", []):
                pred, result = bet.get("prediction"), bet.get("result")
                if result == "WIN": history.append(pred)
                elif result == "LOSE": history.append("DOWN" if pred == "UP" else "UP")
            self.market_history = history[::-1]
        except: self.market_history = []

    def start_betting(self, session, session_id, address):
        self.log(f"Starting Game Session ({self.max_bets} Rounds)", "BET")
        self.fetch_market_history(session, address)
        for i in range(self.max_bets):
            prediction = random.choice(["UP", "DOWN"]) if not self.market_history else ("DOWN" if self.market_history[-1] == "UP" else "UP")
            try:
                resp = session.post("https://hub.aixcrypto.ai/api/game/bet", json={"prediction": prediction, "sessionId": session_id})
                if resp.status_code in [200, 201]:
                    data = resp.json()
                    if data.get("success"):
                        round_id = data.get("bet", {}).get("roundId")
                        self.log(f"Bet #{i+1} | {prediction} | Round: {round_id}", "AI")
                        time.sleep(15)
                time.sleep(5)
            except Exception as e: self.log(f"Bet Error: {e}", "ERROR")

    def login_process(self, private_key, proxy=None):
        try:
            account = Account.from_key(private_key)
            addr = account.address
            self.log(f"Wallet : {addr[:6]}...{addr[-4:]}", "INFO")
            captcha_token = self.solve_turnstile()
            if not captcha_token:
                self.log("Captcha Failed", "ERROR")
                return

            with requests.Session(impersonate="chrome124", proxies={"http": proxy, "https": proxy} if proxy else None) as s:
                s.headers.update({
                    "authority": "auth.privy.io",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "origin": "https://hub.aixcrypto.ai",
                    "referer": "https://hub.aixcrypto.ai/",
                    "privy-app-id": self.privy_app_id,
                    "privy-client": "react-auth:3.10.1"
                })

                # SIWE Init - Nonce ရအောင်ယူခြင်း
                init_res = s.post("https://auth.privy.io/api/v1/siwe/init", json={"address": addr, "token": captcha_token})
                if init_res.status_code != 200:
                    self.log(f"Privy Init Failed: {init_res.text}", "ERROR")
                    return
                
                init_data = init_res.json()
                nonce = init_data.get('nonce')
                if not nonce:
                    self.log("Nonce not found in response", "ERROR")
                    return

                issued_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                msg = f"hub.aixcrypto.ai wants you to sign in with your Ethereum account:\n{addr}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://hub.aixcrypto.ai\nVersion: 1\nChain ID: 560048\nNonce: {nonce}\nIssued At: {issued_at}\nResources:\n- https://privy.io"
                sig = account.sign_message(encode_defunct(text=msg)).signature.hex()

                # Privy Authenticate
                auth_res = s.post("https://auth.privy.io/api/v1/siwe/authenticate", json={
                    "chainId": "eip155:560048", "connectorType": "injected", "message": msg,
                    "mode": "login-or-sign-up", "signature": sig, "walletClientType": "metamask"
                })
                
                if auth_res.status_code == 200:
                    token = auth_res.json().get('token')
                    s.cookies.set("privy-token", token, domain="hub.aixcrypto.ai")
                    
                    # App Login
                    ts = int(time.time() * 1000)
                    msg_app = f"Sign this message to authenticate with AIxCrypto.\n\nWallet: {addr.lower()}\nTimestamp: {ts}\n\nThis signature will not trigger any blockchain transaction or cost any gas fees."
                    sig_app = account.sign_message(encode_defunct(text=msg_app)).signature.hex()
                    
                    login_res = s.post("https://hub.aixcrypto.ai/api/login", json={"address": addr, "message": msg_app, "signature": sig_app})
                    if login_res.status_code == 200:
                        self.log("Login Success!", "SUCCESS")
                        sess_id = login_res.json().get("sessionId")
                        s.post("https://hub.aixcrypto.ai/api/tasks/claim", json={"taskId": 1, "sessionId": sess_id})
                        self.start_betting(s, sess_id, addr)
                        s.post("https://hub.aixcrypto.ai/api/tasks/claim-all", json={"sessionId": sess_id})
                    else: self.log("AIxC Login Failed", "ERROR")
                else: self.log("Privy Auth Failed", "ERROR")
        except Exception as e: self.log(f"Error: {e}", "ERROR")

    def run(self):
        self.load_files()
        self.print_banner()
        self.show_menu()
        cycle = 1
        while True:
            self.log(f"Cycle #{cycle} Started", "CYCLE")
            for i, pk in enumerate(self.accounts):
                self.login_process(pk, self.proxies[i % len(self.proxies)] if self.use_proxy else None)
            self.log(f"Cycle #{cycle} Complete", "CYCLE")
            cycle += 1
            time.sleep(86400)

if __name__ == "__main__":
    AixCryptoBot().run()
