import os
import time
import json
import random
import asyncio
import requests
import websockets
from datetime import datetime
from colorama import Fore, Style, init
from web3 import Web3
from eth_account.messages import encode_defunct
from rich.console import Console
from rich.progress import ProgressBar
from rich.panel import Panel
from rich.live import Live

init(autoreset=True)
console = Console()

class Logger:
    @staticmethod
    def _get_timestamp():
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def info(msg, context=""):
        ctx = f"[{context}] " if context else ""
        print(f"[ {Fore.LIGHTBLACK_EX}{Logger._get_timestamp()}{Style.RESET_ALL} ] ℹ️  {Fore.GREEN}INFO{Style.RESET_ALL} {ctx.ljust(20)}{msg}")

    @staticmethod
    def warn(msg, context=""):
        ctx = f"[{context}] " if context else ""
        print(f"[ {Fore.LIGHTBLACK_EX}{Logger._get_timestamp()}{Style.RESET_ALL} ] ⚠️  {Fore.YELLOW}WARN{Style.RESET_ALL} {ctx.ljust(20)}{msg}")

    @staticmethod
    def error(msg, context=""):
        ctx = f"[{context}] " if context else ""
        print(f"[ {Fore.LIGHTBLACK_EX}{Logger._get_timestamp()}{Style.RESET_ALL} ] ❌ {Fore.RED}ERROR{Style.RESET_ALL} {ctx.ljust(20)}{msg}")

def get_random_user_agent():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    ]
    return random.choice(user_agents)

def get_headers(privy_token=None, is_privy=False):
    headers = {
        'accept': 'application/json',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://hub.aixcrypto.ai',
        'referer': 'https://hub.aixcrypto.ai/',
        'user-agent': get_random_user_agent()
    }
    if is_privy:
        headers['privy-app-id'] = 'cmk3zw8d704bxl70chtewm6hd'
        headers['privy-ca-id'] = '119aa643-ca62-45b4-b305-e0fab44f33ae'
        headers['privy-client'] = 'react-auth:3.10.1'
    if privy_token:
        headers['cookie'] = f"privy-token={privy_token}"
    return headers

async def solve_captcha(api_key):
    site_key = '0x4AAAAAAAM8ceq5KhP1uJBt'
    page_url = 'https://hub.aixcrypto.ai/'
    
    try:
        # Submit to 2captcha
        submit_url = f"http://2captcha.com/in.php?key={api_key}&method=turnstile&sitekey={site_key}&pageurl={page_url}&json=1"
        res = requests.get(submit_url).json()
        
        if res.get('status') != 1:
            return None
            
        captcha_id = res['request']
        Logger.info("Solving Cloudflare captcha...", "Captcha")
        
        for _ in range(20):
            await asyncio.sleep(5)
            check_url = f"http://2captcha.com/res.php?key={api_key}&action=get&id={captcha_id}&json=1"
            status_res = requests.get(check_url).json()
            if status_res.get('status') == 1:
                return status_res['request']
        return None
    except Exception as e:
        Logger.error(f"Captcha error: {str(e)}")
        return None

async def perform_login(private_key, proxy, captcha_api_key, context):
    w3 = Web3()
    account = w3.eth.account.from_key(private_key)
    address = account.address

    # 1. Solve Captcha
    captcha_token = await solve_captcha(captcha_api_key)
    if not captcha_token: return None

    # 2. Privy Login
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    try:
        # Init SIWE
        res_init = requests.post(
            'https://auth.privy.io/api/v1/siwe/init',
            json={'address': address, 'token': captcha_token},
            headers=get_headers(is_privy=True),
            proxies=proxies
        ).json()
        
        nonce = res_init['nonce']
        issued_at = datetime.utcnow().isoformat() + "Z"
        
        message_text = (
            f"hub.aixcrypto.ai wants you to sign in with your Ethereum account:\n{address}\n\n"
            f"By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\n"
            f"URI: https://hub.aixcrypto.ai\nVersion: 1\nChain ID: 24101\nNonce: {nonce}\nIssued At: {issued_at}\nResources:\n- https://privy.io"
        )
        
        signature = account.sign_message(encode_defunct(text=message_text)).signature.hex()
        
        # Authenticate
        res_auth = requests.post(
            'https://auth.privy.io/api/v1/siwe/authenticate',
            json={
                'message': message_text,
                'signature': signature,
                'chainId': 'eip155:24101',
                'walletClientType': 'metamask',
                'connectorType': 'injected',
                'mode': 'login-or-sign-up'
            },
            headers=get_headers(is_privy=True),
            proxies=proxies
        ).json()
        
        privy_token = res_auth.get('token')
        if not privy_token: return None

        # 3. AIxC Login Challenge
        res_chall = requests.get(
            f'https://hub.aixcrypto.ai/api/users/auth/challenge?address={address.lower()}',
            headers=get_headers(privy_token),
            proxies=proxies
        ).json()
        
        chall_msg = res_chall['message']
        sig_chall = account.sign_message(encode_defunct(text=chall_msg)).signature.hex()
        
        # Final Login
        res_login = requests.post(
            'https://hub.aixcrypto.ai/api/login',
            json={'address': address.lower(), 'signature': sig_chall, 'message': chall_msg},
            headers=get_headers(privy_token),
            proxies=proxies
        ).json()
        
        if 'sessionId' in res_login:
            return {
                'address': address,
                'sessionId': res_login['sessionId'],
                'username': res_login.get('username', 'N/A'),
                'privyToken': privy_token
            }
    except Exception as e:
        Logger.error(f"Login failed: {str(e)}", context)
    return None

async def play_game(address, session_id, proxy, privy_token, context, max_plays):
    uri = "wss://hub.aixcrypto.ai/ws"
    bets_placed = 0
    
    try:
        async with websockets.connect(uri) as ws:
            await ws.send(json.dumps({"type": "register", "payload": {"address": address}}))
            Logger.info("WebSocket connected", context)
            
            while bets_placed < max_plays:
                msg = await ws.recv()
                data = json.loads(msg)
                
                if data.get('type') == 'round_start':
                    prediction = random.choice(['UP', 'DOWN'])
                    res = requests.post(
                        'https://hub.aixcrypto.ai/api/game/bet',
                        json={"prediction": prediction, "sessionId": session_id},
                        headers=get_headers(privy_token),
                        proxies={"http": proxy, "https": proxy} if proxy else None
                    ).json()
                    
                    if res.get('success'):
                        bets_placed += 1
                        Logger.info(f"Bet placed: {prediction} ({bets_placed}/{max_plays})", context)
                
                elif data.get('type') == 'user_settlement' and data['data']['userAddress'] == address.lower():
                    result = data['data']['result']
                    reward = data['data']['creditsReward']
                    Logger.info(f"Result: {result} | Reward: {reward}", context)
            
            return bets_placed
    except Exception as e:
        Logger.error(f"WebSocket Error: {str(e)}", context)
        return bets_placed

async def process_account(pk, index, total, proxy, captcha_key):
    context = f"Acc {index+1}/{total}"
    Logger.info("Starting account processing...", context)
    
    login_info = await perform_login(pk, proxy, captcha_key, context)
    if not login_info:
        return
        
    addr, sid, p_token = login_info['address'], login_info['sessionId'], login_info['privyToken']
    Logger.info(f"Logged in as {login_info['username']}", context)

    # Fetch Limits & Play
    try:
        res_limit = requests.get(
            f'https://hub.aixcrypto.ai/api/game/current-round?address={addr}',
            headers=get_headers(p_token)
        ).json()
        
        remaining = res_limit.get('dailyBetRemaining', 0)
        if remaining > 0:
            Logger.info(f"Available Plays: {remaining}", context)
            await play_game(addr, sid, proxy, p_token, context, remaining)
        else:
            Logger.warn("No plays left for today", context)

        # Tasks Claiming
        res_tasks = requests.get(
            f'https://hub.aixcrypto.ai/api/tasks/daily?address={addr}',
            headers=get_headers(p_token)
        ).json()
        
        for task in res_tasks.get('tasks', []):
            if task['isCompleted'] == 1 and task['isClaimed'] == 0:
                requests.post(
                    'https://hub.aixcrypto.ai/api/tasks/claim',
                    json={'taskId': task['id'], 'sessionId': sid},
                    headers=get_headers(p_token)
                )
                Logger.info(f"Claimed Task: {task['title']}", context)
                
    except Exception as e:
        Logger.error(f"Error: {str(e)}", context)

async def main():
    console.print(Panel("[bold cyan]AIxC AUTO DAILY BOT[/bold cyan]\n[magenta]ADB NODE[/magenta]", expand=False))
    
    if not os.path.exists('accounts.txt'):
        Logger.error("accounts.txt not found!")
        return
    
    if not os.path.exists('2captcha.txt'):
        Logger.error("2captcha.txt not found!")
        return

    with open('accounts.txt', 'r') as f:
        pks = [line.strip() for line in f if line.strip()]
    
    with open('2captcha.txt', 'r') as f:
        captcha_key = f.read().strip()

    proxies = []
    if os.path.exists('proxy.txt'):
        with open('proxy.txt', 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]

    use_proxy = input(f"{Fore.CYAN}Use proxy? (y/n): ").lower() == 'y'

    while True:
        for i, pk in enumerate(pks):
            proxy = proxies[i % len(proxies)] if use_proxy and proxies else None
            await process_account(pk, i, len(pks), proxy, captcha_key)
            await asyncio.sleep(5)
            
        Logger.info("Cycle completed. Waiting 24 hours...")
        await asyncio.sleep(86400)

if __name__ == "__main__":
    asyncio.run(main())
