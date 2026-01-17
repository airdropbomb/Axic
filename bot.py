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
        self.api_key_2captcha = ""

    def log(self, message, level="INFO"):
        time_str = datetime.now().strftime('%H:%M:%S')
        colors = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "ERROR": Fore.RED, "CYCLE": Fore.MAGENTA}
        print(f"[{time_str}] {colors.get(level, Fore.WHITE)}[{level}] {message}{Style.RESET_ALL}")

    def load_files(self):
        try:
            with open("2captcha.txt", "r") as f: self.api_key_2captcha = f.read().strip()
            with open("accounts.txt", "r") as f: self.accounts = [l.strip() for l in f if l.strip()]
            if os.path.exists("proxy.txt"):
                with open("proxy.txt", "r") as f: self.proxies = [l.strip() for l in f if l.strip()]
        except Exception as e:
            self.log(f"File Error: {e}", "ERROR")
            sys.exit()

    def solve_turnstile(self):
        import requests as r_sync
        try:
            p = {"key": self.api_key_2captcha, "method": "turnstile", "sitekey": self.sitekey, "pageurl": self.page_url, "json": 1}
            res = r_sync.post("http://2captcha.com/in.php", data=p).json()
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

            with requests.Session(impersonate="chrome124", proxies={"http": proxy, "https": proxy} if proxy else None) as s:
                # Screenshot ထဲက Header များအတိုင်း (Privy-Ca-Id ကိုပါ Dynamic ထည့်ပေးထားပါတယ်)
                ca_id = f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-4{random.randint(100, 999)}-a{random.randint(100, 999)}-{random.randint(100000000000, 999999999999)}"
                s.headers.update({
                    "authority": "auth.privy.io",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "privy-app-id": self.privy_app_id,
                    "privy-ca-id": ca_id,
                    "privy-client": "react-auth:3.10.1",
                    "origin": "https://hub.aixcrypto.ai",
                    "referer": "https://hub.aixcrypto.ai/"
                })
                
                # 1. SIWE Init
                init_res = s.post("https://auth.privy.io/api/v1/siwe/init", json={"address": addr, "token": token})
                nonce = init_res.json().get('nonce')
                if not nonce: return self.log("No Nonce", "ERROR")

                # 2. Sign Message (Screenshot ထဲက Format အတိုင်း ၁၀၀% တူအောင် ပြင်ထားပါတယ်)
                # Chain ID 42161 ကို သုံးထားပါတယ်
                now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                msg = (
                    f"hub.aixcrypto.ai wants you to sign in with your Ethereum account:\n"
                    f"{addr}\n\n"
                    f"By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\n"
                    f"URI: https://hub.aixcrypto.ai\n"
                    f"Version: 1\n"
                    f"Chain ID: 42161\n"
                    f"Nonce: {nonce}\n"
                    f"Issued At: {now_iso}\n"
                    f"Resources:\n"
                    f"- https://privy.io"
                )
                
                sig = account.sign_message(encode_defunct(text=msg)).signature.hex()

                # 3. Privy Authenticate
                auth_payload = {
                    "chainId": "eip155:42161",
                    "connectorType": "injected",
                    "message": msg,
                    "mode": "login-or-sign-up",
                    "signature": sig,
                    "walletClientType": "metamask"
                }
                auth_res = s.post("https://auth.privy.io/api/v1/siwe/authenticate", json=auth_payload)
                
                if auth_res.status_code != 200:
                    self.log(f"Privy Auth Failed: {auth_res.text}", "ERROR")
                    return

                privy_token = auth_res.json().get('token')
                s.cookies.set("privy-token", privy_token, domain="hub.aixcrypto.ai")

                # 4. App Login (Screenshot ထဲက ဒုတိယ Signature - AlxCrypto Auth)
                # ဒုတိယ sign အတွက် timestamp ကို screenshot အတိုင်း format ပြင်ပါတယ်
                ts = int(time.time() * 1000)
                msg_app = (
                    f"Sign this message to authenticate with AIxCrypto.\n\n"
                    f"Wallet: {addr.lower()}\n"
                    f"Timestamp: {ts}\n\n"
                    f"This signature will not trigger any blockchain transaction or cost any gas fees."
                )
                sig_app = account.sign_message(encode_defunct(text=msg_app)).signature.hex()
                
                login_res = s.post("https://hub.aixcrypto.ai/api/login", json={
                    "address": addr,
                    "message": msg_app,
                    "signature": sig_app
                })
                
                if login_res.status_code == 200:
                    self.log("Login Success!", "SUCCESS")
                    data = login_res.json()
                    sess_id = data.get('sessionId')
                    s.post("https://hub.aixcrypto.ai/api/tasks/claim", json={"taskId": 1, "sessionId": sess_id})
                    self.log("Daily Task Claimed", "SUCCESS")
                else:
                    self.log("AIxC Login Failed", "ERROR")

        except Exception as e: self.log(f"Error: {e}", "ERROR")

    def run(self):
        self.load_files()
        while True:
            for i, pk in enumerate(self.accounts):
                self.login_process(pk, self.proxies[i%len(self.proxies)] if self.use_proxy else None)
            time.sleep(86400)

if __name__ == "__main__":
    bot = AixCryptoBot()
    bot.run()
