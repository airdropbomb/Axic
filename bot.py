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

# Terminal ကို ရှင်းထုတ်ခြင်း
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
{Fore.WHITE}By: ADB NODE{Style.RESET_ALL}
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
        if message == "Processing Daily Check-in...":
            color = Fore.GREEN
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
        print(f"1. Run with Proxy\n2. Run without Proxy")
        choice = input(f"{Fore.GREEN}Select Mode (1/2): {Style.RESET_ALL}").strip()
        self.use_proxy = True if choice == '1' else False
        
        print(f"{Fore.CYAN}============================================================{Style.RESET_ALL}")
        print(f"1. 2Captcha\n2. SCTG")
        solver_choice = input(f"{Fore.GREEN}Select Solver (1/2): {Style.RESET_ALL}").strip()
        self.solver_type = "sctg" if solver_choice == '2' else "2captcha"

        print(f"{Fore.CYAN}============================================================{Style.RESET_ALL}")
        input_bet = input(f"{Fore.GREEN}Enter Max Bets per Account : {Style.RESET_ALL}").strip()
        self.max_bets = int(input_bet) if input_bet else 5

    def solve_turnstile_2captcha(self):
        self.log("Solving Captcha with 2Captcha...", "INFO")
        import requests as r_sync
        try:
            payload = {"key": self.api_key_2captcha, "method": "turnstile", "sitekey": self.sitekey, "pageurl": self.page_url, "json": 1}
            resp = r_sync.post("http://2captcha.com/in.php", data=payload).json()
            if resp.get('status') != 1: return None
            req_id = resp.get('request')
            for _ in range(30):
                time.sleep(4)
                res = r_sync.get(f"http://2captcha.com/res.php?key={self.api_key_2captcha}&action=get&id={req_id}&json=1").json()
                if res.get('status') == 1: return res.get('request')
        except: return None
        return None

    def solve_turnstile_sctg(self):
        self.log("Solving Captcha with SCTG...", "INFO")
        import requests as r_sync
        from urllib.parse import urlencode
        params = {"key": self.api_key_sctg, "method": "turnstile", "pageurl": self.page_url, "sitekey": self.sitekey}
        try:
            response = r_sync.get("https://sctg.xyz/in.php?" + urlencode(params), timeout=30)
            if "|" not in response.text: return None
            task_id = response.text.split("|")[1]
            for _ in range(60):
                time.sleep(5)
                poll = r_sync.get(f"https://sctg.xyz/res.php?key={self.api_key_sctg}&id={task_id}&action=get", timeout=30)
                if "OK|" in poll.text: return poll.text.split("|")[1]
        except: return None
        return None

    def solve_turnstile(self):
        return self.solve_turnstile_sctg() if self.solver_type == "sctg" else self.solve_turnstile_2captcha()

    def fetch_market_history(self, session, address):
        self.log("AI: Analyzing market history...", "INFO")
        history = []
        try:
            for page in range(1, 4):
                url = f"https://hub.aixcrypto.ai/api/game/bet-history?address={address}&page={page}&pageSize=10"
                resp = session.get(url).json()
                bet_list = resp.get("list", [])
                if not bet_list: break
                for bet in bet_list:
                    pred, result = bet.get("prediction"), bet.get("result")
                    if result == "WIN": history.append(pred)
                    elif result == "LOSE": history.append("DOWN" if pred == "UP" else "UP")
            self.market_history = history[::-1]
            self.log(f"AI: Loaded {len(self.market_history)} historical data points.", "AI")
        except: self.market_history = []

    def predict_next_move(self):
        if not self.market_history or len(self.market_history) < 3:
            return random.choice(["UP", "DOWN"]), "Random (Gathering Data)"
        recent = self.market_history[-5:]
        if len(recent) >= 3:
            if recent[-1] == recent[-2] == recent[-3] == "UP": return "DOWN", "Anti-Streak (Overbought)"
            if recent[-1] == recent[-2] == recent[-3] == "DOWN": return "UP", "Anti-Streak (Oversold)"
        return ("DOWN" if self.market_history[-1] == "UP" else "UP"), "Smart Reversal"

    def claim_daily(self, session, session_id):
        self.log("Processing Daily Check-in...", "INFO")
        try:
            resp = session.post("https://hub.aixcrypto.ai/api/tasks/claim", json={"taskId": 1, "sessionId": session_id})
            if resp.status_code == 200 and resp.json().get("success"):
                self.log(f"Daily Claim Success! Reward: +{resp.json().get('reward')}", "SUCCESS")
            else: self.log("Daily Claim Failed/Already Claimed", "WARNING")
        except: pass

    def claim_all_tasks(self, session, session_id):
        self.log("Processing Claim All Tasks...", "TASK")
        try:
            resp = session.post("https://hub.aixcrypto.ai/api/tasks/claim-all", json={"sessionId": session_id})
            if resp.status_code == 200 and resp.json().get("success"):
                self.log(f"Claim All Success! Reward: +{resp.json().get('totalReward')}", "SUCCESS")
        except: pass

    def get_user_stats(self, session, address):
        try:
            resp = session.get(f"https://hub.aixcrypto.ai/api/user/{address}").json()
            self.log(f"Credits: {resp.get('credits')} | Win Rate: {resp.get('winRate', 0):.2f}%", "SUCCESS")
        except: pass

    def check_bet_result(self, session, address, round_id):
        try:
            resp = session.get(f"https://hub.aixcrypto.ai/api/game/bet-history?address={address}&page=1&pageSize=10").json()
            for bet in resp.get("list", []):
                if str(bet.get("round_id")) == str(round_id):
                    return bet.get("result", "PENDING"), bet.get("credits_reward", 0)
        except: pass
        return "UNKNOWN", 0

    def start_betting(self, session, session_id, address):
        self.log(f"Starting Game Session ({self.max_bets} Rounds)", "BET")
        self.fetch_market_history(session, address)
        i = 0
        while i < self.max_bets:
            prediction, reason = self.predict_next_move()
            try:
                resp = session.post("https://hub.aixcrypto.ai/api/game/bet", json={"prediction": prediction, "sessionId": session_id})
                if resp.status_code in [200, 201] and resp.json().get("success"):
                    round_id = resp.json().get("bet", {}).get("roundId")
                    self.log(f"Bet #{i+1} | {prediction} | AI: {reason}", "AI")
                    time.sleep(12)
                    res, reward = self.check_bet_result(session, address, round_id)
                    self.log(f"Result: {res} | Reward: {reward}", "SUCCESS" if res == "WIN" else "LOSE")
                    i += 1
                time.sleep(5)
            except Exception as e:
                self.log(f"Bet Error: {e}", "ERROR")
                time.sleep(5)

    def login_process(self, private_key, proxy=None):
        try:
            account = Account.from_key(private_key)
            addr = account.address
            self.log(f"Wallet : {addr[:6]}...{addr[-4:]}", "INFO")
            
            captcha_token = self.solve_turnstile()
            if not captcha_token: return

            with requests.Session(impersonate="chrome124", proxies={"http": proxy, "https": proxy} if proxy else None) as s:
                s.headers.update({"privy-app-id": self.privy_app_id, "privy-client": "react-auth:3.10.1"})
                
                # SIWE Init
                init_res = s.post("https://auth.privy.io/api/v1/siwe/init", json={"address": addr, "token": captcha_token}).json()
                nonce = init_res['nonce']
                issued_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                
                msg = f"hub.aixcrypto.ai wants you to sign in with your Ethereum account:\n{addr}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://hub.aixcrypto.ai\nVersion: 1\nChain ID: 560048\nNonce: {nonce}\nIssued At: {issued_at}\nResources:\n- https://privy.io"
                sig = account.sign_message(encode_defunct(text=msg)).signature.hex()

                # Privy Auth
                auth_res = s.post("https://auth.privy.io/api/v1/siwe/authenticate", json={
                    "chainId": "eip155:560048", "connectorType": "injected", "message": msg,
                    "mode": "login-or-sign-up", "signature": sig, "walletClientType": "metamask"
                }).json()
                
                s.cookies.set("privy-token", auth_res['token'], domain="hub.aixcrypto.ai")
                
                # App Login
                ts = int(time.time() * 1000)
                msg_app = f"Sign this message to authenticate with AIxCrypto.\n\nWallet: {addr.lower()}\nTimestamp: {ts}\n\nThis signature will not trigger any blockchain transaction or cost any gas fees."
                sig_app = account.sign_message(encode_defunct(text=msg_app)).signature.hex()

                login_res = s.post("https://hub.aixcrypto.ai/api/login", json={"address": addr, "message": msg_app, "signature": sig_app})
                if login_res.status_code == 200:
                    self.log("Login Success!", "SUCCESS")
                    sess_id = login_res.json().get("sessionId")
                    self.claim_daily(s, sess_id)
                    self.start_betting(s, sess_id, addr)
                    self.claim_all_tasks(s, sess_id)
                    self.get_user_stats(s, addr)
        except Exception as e: self.log(f"Account Error: {e}", "ERROR")

    def run(self):
        self.load_files()
        self.print_banner()
        self.show_menu()
        cycle = 1
        while True:
            self.log(f"Cycle #{cycle} Started", "CYCLE")
            for i, pk in enumerate(self.accounts):
                self.login_process(pk, (self.proxies[i % len(self.proxies)] if self.use_proxy else None))
            self.log(f"Cycle #{cycle} Complete", "CYCLE")
            cycle += 1
            time.sleep(86400)

if __name__ == "__main__":
    AixCryptoBot().run()
