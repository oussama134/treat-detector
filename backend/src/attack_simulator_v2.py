# attack_simulator_v2.py - Advanced attack patterns that match CICIDS signatures
"""
Advanced attack simulator that generates traffic patterns matching CICIDS2017 characteristics.
⚠️  USE ONLY ON YOUR OWN NETWORK FOR TESTING
"""

import socket
import time
import threading
import random
import struct
from datetime import datetime

print("""
╔════════════════════════════════════════════════════╗
║   ADVANCED ATTACK SIMULATOR v2.0 (TEST ONLY)      ║
║   ⚠️  USE ONLY ON YOUR OWN NETWORK  ⚠️             ║
║                                                    ║
║   Generates CICIDS-like attack patterns:          ║
║   • DoS GoldenEye (HTTP flood)                    ║
║   • DoS Slowhttptest (Slow HTTP)                  ║
║   • DoS Hulk (HTTP GET flood)                     ║
║   • PortScan (Sequential scan)                    ║
║   • Bot (C&C traffic)                             ║
╚════════════════════════════════════════════════════╝
""")

LOCAL_IP = "127.0.0.1"
TARGET_PORTS = [80, 443, 8080, 8443, 3000, 5000]

def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")

# =============================================================================
# DoS GoldenEye - HTTP POST flood with random data
# =============================================================================
def dos_goldeneye():
    """
    GoldenEye signature:
    - High-rate HTTP POST requests
    - Large payloads (1KB-10KB)
    - Keep-alive connections
    - Random headers
    """
    log("🔥 Starting DoS GoldenEye (HTTP POST flood)...")
    
    for i in range(200):  # 200 requests
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            # Try to connect to local web server
            port = random.choice([80, 8080, 3000, 5000])
            sock.connect((LOCAL_IP, port))
            
            # HTTP POST with large payload
            payload_size = random.randint(1024, 10240)  # 1KB-10KB
            payload = "X" * payload_size
            
            http_request = (
                f"POST /api/test HTTP/1.1\r\n"
                f"Host: {LOCAL_IP}\r\n"
                f"User-Agent: Mozilla/5.0 (compatible; GoldenEye/1.0)\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"\r\n{payload}"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            
            # Small delay to create recognizable pattern
            time.sleep(0.01)
            
        except Exception:
            pass  # Silent failure (ports may not be open)
    
    log("✓ DoS GoldenEye complete (200 POST requests)")

# =============================================================================
# DoS Slowhttptest - Slow HTTP headers
# =============================================================================
def dos_slowhttptest():
    """
    Slowhttptest signature:
    - Slow HTTP header transmission
    - Keep connections open
    - Send headers byte-by-byte
    - Long duration per connection
    """
    log("🐌 Starting DoS Slowhttptest (Slow HTTP headers)...")
    
    sockets = []
    
    # Open multiple slow connections
    for i in range(50):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            port = random.choice([80, 8080, 3000])
            sock.connect((LOCAL_IP, port))
            
            # Send partial HTTP request
            sock.send(b"GET / HTTP/1.1\r\n")
            time.sleep(0.1)
            sock.send(f"Host: {LOCAL_IP}\r\n".encode())
            time.sleep(0.1)
            sock.send(b"User-Agent: SlowHTTPTest\r\n")
            
            sockets.append(sock)
        except Exception:
            pass
    
    # Keep sending slow headers
    for _ in range(10):
        for sock in sockets:
            try:
                sock.send(f"X-Header-{random.randint(1,1000)}: value\r\n".encode())
                time.sleep(0.5)
            except Exception:
                pass
    
    # Close all
    for sock in sockets:
        try:
            sock.close()
        except Exception:
            pass
    
    log(f"✓ DoS Slowhttptest complete ({len(sockets)} slow connections)")

# =============================================================================
# DoS Hulk - HTTP GET flood
# =============================================================================
def dos_hulk():
    """
    Hulk signature:
    - Rapid HTTP GET requests
    - Random URLs
    - User-Agent randomization
    - High packet rate
    """
    log("💥 Starting DoS Hulk (HTTP GET flood)...")
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "curl/7.68.0",
        "python-requests/2.25.1"
    ]
    
    for i in range(300):  # 300 rapid requests
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            port = random.choice([80, 8080, 3000])
            sock.connect((LOCAL_IP, port))
            
            # Random URL
            url = f"/{random.choice(['api', 'page', 'data'])}/{random.randint(1, 1000)}"
            ua = random.choice(user_agents)
            
            http_request = (
                f"GET {url} HTTP/1.1\r\n"
                f"Host: {LOCAL_IP}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            
            # Very fast - no delay
            
        except Exception:
            pass
    
    log("✓ DoS Hulk complete (300 GET requests)")

# =============================================================================
# PortScan - Sequential port scanning
# =============================================================================
def portscan():
    """
    PortScan signature:
    - Sequential port probing
    - SYN packets to multiple ports
    - Fast scanning rate
    - Connection attempts without data
    """
    log("🔍 Starting PortScan (sequential scan)...")
    
    # Scan ports 1-500
    scanned = 0
    for port in range(1, 500, 5):  # Every 5th port
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            result = sock.connect_ex((LOCAL_IP, port))
            sock.close()
            scanned += 1
        except Exception:
            pass
    
    log(f"✓ PortScan complete ({scanned} ports scanned)")

# =============================================================================
# Bot - Command & Control traffic
# =============================================================================
def bot_traffic():
    """
    Bot signature:
    - Periodic beaconing to C&C
    - Small data packets
    - Regular intervals
    - Predictable pattern
    """
    log("🤖 Starting Bot traffic (C&C beaconing)...")
    
    for i in range(30):  # 30 beacon attempts
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Try to connect to "C&C server" (local port)
            port = random.choice([4444, 5555, 6666, 7777])
            sock.connect((LOCAL_IP, port))
            
            # Send small beacon packet
            beacon = b"BEACON:" + struct.pack('I', random.randint(1000, 9999))
            sock.send(beacon)
            sock.close()
            
        except Exception:
            pass
        
        # Regular interval (every 2 seconds)
        time.sleep(2)
    
    log("✓ Bot traffic complete (30 beacons)")

# =============================================================================
# DDoS - Distributed flood simulation
# =============================================================================
def ddos_simulation():
    """
    DDoS signature:
    - Multiple source patterns
    - UDP flood
    - High packet rate
    - Variable packet sizes
    """
    log("🌊 Starting DDoS simulation (UDP flood)...")
    
    for i in range(500):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Variable packet sizes (100-1400 bytes)
            size = random.randint(100, 1400)
            message = b"D" * size
            
            port = random.choice([9999, 10000, 10001])
            sock.sendto(message, (LOCAL_IP, port))
            sock.close()
            
        except Exception:
            pass
    
    log("✓ DDoS simulation complete (500 UDP packets)")

# =============================================================================
# Web Attack patterns
# =============================================================================
def web_attacks():
    """
    Web Attack signatures:
    - SQL injection attempts
    - XSS payloads
    - Path traversal
    - Malformed requests
    """
    log("🕷️  Starting Web Attacks (SQLi, XSS, etc.)...")
    
    payloads = [
        # SQL Injection
        "/?id=1' OR '1'='1",
        "/?user=admin'--",
        "/?q=1 UNION SELECT * FROM users",
        # XSS
        "/?search=<script>alert(1)</script>",
        "/?name=<img src=x onerror=alert(1)>",
        # Path Traversal
        "/../../../etc/passwd",
        "/../../windows/system32/config/sam",
        # Command Injection
        "/?cmd=; ls -la",
        "/?exec=| whoami"
    ]
    
    for payload in payloads * 10:  # 90 attack requests
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            port = random.choice([80, 8080, 3000])
            sock.connect((LOCAL_IP, port))
            
            http_request = (
                f"GET {payload} HTTP/1.1\r\n"
                f"Host: {LOCAL_IP}\r\n"
                f"User-Agent: sqlmap/1.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            sock.send(http_request)
            sock.close()
            
            time.sleep(0.05)
            
        except Exception:
            pass
    
    log("✓ Web Attacks complete (90 malicious requests)")

# =============================================================================
# Main execution
# =============================================================================
def run_attack_scenario(scenario="all"):
    """Run specific attack scenario or all"""
    
    attacks = {
        "goldeneye": dos_goldeneye,
        "slowhttp": dos_slowhttptest,
        "hulk": dos_hulk,
        "portscan": portscan,
        "bot": bot_traffic,
        "ddos": ddos_simulation,
        "web": web_attacks
    }
    
    if scenario == "all":
        log("🚀 Starting ALL attack scenarios...")
        log("=" * 60)
        
        threads = []
        for name, func in attacks.items():
            thread = threading.Thread(target=func, name=name)
            threads.append(thread)
            thread.start()
            time.sleep(2)  # Stagger attacks
        
        # Wait for all to complete
        for thread in threads:
            thread.join()
        
        log("=" * 60)
        log("✅ ALL attacks complete!")
        log("📊 Check your dashboard - you should see multiple attack types")
        log("💡 Tip: If still seeing only DoS, increase confidence threshold to 0.85")
        
    elif scenario in attacks:
        log(f"🎯 Running single attack: {scenario}")
        attacks[scenario]()
        log(f"✅ {scenario} complete!")
    else:
        print(f"Unknown scenario: {scenario}")
        print(f"Available: {', '.join(attacks.keys())}, all")

if __name__ == "__main__":
    print("Available attack scenarios:")
    print("  1. goldeneye  - DoS GoldenEye (HTTP POST flood)")
    print("  2. slowhttp   - DoS Slowhttptest (Slow headers)")
    print("  3. hulk       - DoS Hulk (HTTP GET flood)")
    print("  4. portscan   - Port scanning")
    print("  5. bot        - Bot C&C traffic")
    print("  6. ddos       - DDoS UDP flood")
    print("  7. web        - Web attacks (SQLi, XSS)")
    print("  8. all        - Run ALL attacks (recommended)")
    print()
    
    choice = input("Select scenario (1-8 or name) [all]: ").strip().lower()
    
    # Map numbers to names
    scenario_map = {
        "1": "goldeneye", "2": "slowhttp", "3": "hulk",
        "4": "portscan", "5": "bot", "6": "ddos",
        "7": "web", "8": "all", "": "all"
    }
    
    scenario = scenario_map.get(choice, choice)
    
    confirm = input(f"\n⚠️  Start {scenario} attack simulation? (yes/no): ").lower()
    
    if confirm == "yes":
        print("\n⚠️  Starting in 3 seconds...")
        time.sleep(3)
        run_attack_scenario(scenario)
    else:
        print("Aborted.")