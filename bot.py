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
init(autoreset=True)

class AixCryptoBot:
    def __init__(self):
        self.sitekey = "0x4AAAAAAAM8ceq5KhP1uJBt"
        self.page_url = "https://hub.aixcrypto.ai/"
        self.privy_app_id = "cmk3zw8d704bxl70chtewm6hd"
        self.accounts = []
        self.proxies = []
        self.max_bets = 5 
        self.use_proxy = False
        self.solver_type = "2captcha"

    def log(self, message, level="INFO"):
        time_str = datetime.now().strftime('%H:%M:%S')
        colors = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "ERROR": Fore.RED, "CYCLE": Fore.MAGENTA}
        print(f"[{time_str}] {colors.get(level, Fore.WHITE)}[{level}] {message}{Style.RESET_ALL}")

    def load_files(self):
        try:
            with open("2captcha.txt", "r") as f: self.api_key_2captcha = f.read().strip()
            with open("accounts.txt", "r") as f: self.accounts = [line.strip() for line in f if line.strip()]
            if os.path.exists("proxy.txt"):
                with open("proxy.txt", "r") as f: self.proxies = [l.strip() for l in f if l.strip()]
        except Exception as e:
            self.log(f"File Error: {e}", "ERROR")
            sys.exit()

    def solve_turnstile(self):
        import requests as r_sync
        self.log("Solving Captcha via 2Captcha...", "INFO")
        try:
            p = {"key": self.api_key_2captcha, "method": "turnstile", "sitekey": self.sitekey, "pageurl": self.page_url, "json": 1}
            res = r_sync.post("http://2captcha.com/in.php", data=p).json()
            if res.get('status') != 1: return None
            rid = res.get('request')
            for _ in range(20):
                time.sleep(5)
                ans = r_sync.get(f"http://2captcha.com/res.php?key={self.api_key_2captcha}&action=get&id={rid}&json=1").json()
                if ans.get('status') == 1: return ans.get('request')
        except: return None
        return None

    def login_process(self, pk, proxy=None):
        try:
            account = Account.from_key(pk)
            addr = account.address
            self.log(f"Wallet: {addr[:6]}...{addr[-4:]}", "INFO")
            
            token = self.solve_turnstile()
            if not token: return self.log("Captcha Failed", "ERROR")

            proxies = {"http": proxy, "https": proxy} if proxy else None
            with requests.Session(impersonate="chrome124", proxies=proxies) as s:
                # Headers for Privy
                headers = {
                    "authority": "auth.privy.io",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "privy-app-id": self.privy_app_id,
                    "privy-client": "react-auth:3.10.1",
                    "origin": "https://hub.aixcrypto.ai",
                    "referer": "https://hub.aixcrypto.ai/"
                }
                
                # 1. SIWE Init
                init_res = s.post("https://auth.privy.io/api/v1/siwe/init", json={"address": addr, "token": token}, headers=headers)
                nonce = init_res.json().get('nonce')
                if not nonce: return self.log("No Nonce", "ERROR")

                # 2. Sign Message (AIxCrypto current chain is 24101)
                now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                # Chain ID ကို ၂ မျိုးစလုံး စမ်းကြည့်နိုင်အောင် eip155:24101 ကို သုံးထားပါတယ်
                msg = f"hub.aixcrypto.ai wants you to sign in with your Ethereum account:\n{addr}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://hub.aixcrypto.ai\nVersion: 1\nChain ID: 24101\nNonce: {nonce}\nIssued At: {now}\nResources:\n- https://privy.io"
                
                sig = account.sign_message(encode_defunct(text=msg)).signature.hex()

                # 3. Privy Authenticate
                auth_payload = {
                    "chainId": "eip155:24101",
                    "connectorType": "injected",
                    "message": msg,
                    "mode": "login-or-sign-up",
                    "signature": sig,
                    "walletClientType": "metamask"
                }
                auth_res = s.post("https://auth.privy.io/api/v1/siwe/authenticate", json=auth_payload, headers=headers)
                
                if auth_res.status_code != 200:
                    self.log(f"Privy Auth Failed: {auth_res.text}", "ERROR")
                    return

                privy_token = auth_res.json().get('token')
                s.cookies.set("privy-token", privy_token, domain="hub.aixcrypto.ai")

                # 4. App Login
                login_res = s.post("https://hub.aixcrypto.ai/api/login", json={
                    "address": addr,
                    "message": msg,
                    "signature": sig
                })
                
                if login_res.status_code == 200:
                    self.log("Login Success!", "SUCCESS")
                    sess_id = login_res.json().get('sessionId')
                    # Tasks
                    s.post("https://hub.aixcrypto.ai/api/tasks/claim", json={"taskId": 1, "sessionId": sess_id})
                    self.log("Daily Claimed", "SUCCESS")
                else:
                    self.log("AIxC Login Failed", "ERROR")

        except Exception as e: self.log(f"Error: {e}", "ERROR")

    def run(self):
        self.load_files()
        print(f"{Fore.CYAN}AIxCrypto Bot Started | Accounts: {len(self.accounts)}{Style.RESET_ALL}")
        while True:
            for i, pk in enumerate(self.accounts):
                self.login_process(pk, self.proxies[i%len(self.proxies)] if self.use_proxy else None)
            self.log("Cycle Complete. Sleep 24h.", "CYCLE")
            time.sleep(86400)

if __name__ == "__main__":
    bot = AixCryptoBot()
    bot.run()
