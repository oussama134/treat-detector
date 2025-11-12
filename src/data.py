# find_npcap.py - corrected
import subprocess
import re

def find_npcap_interfaces():
    """Find exact Npcap interface names using Windows commands"""
    print("🔍 Finding Npcap Interfaces...")
    
    try:
        # Method 1: Use getmac command
        result = subprocess.run(
            ['getmac', '/fo', 'csv', '/v'], 
            capture_output=True, text=True, encoding='cp1252'
        )
        print("Network Adapters (getmac output):")
        print(result.stdout)
        
        # Method 2: Use ipconfig
        result = subprocess.run(
            ['ipconfig', '/all'], 
            capture_output=True, text=True, encoding='cp1252'
        )
        print("\nDetailed Network Info (ipconfig):")
        print(result.stdout)
        
        # Extract interface names
        interfaces = re.findall(r"([A-Za-z0-9\s\-\*]+)\s*Adapter", result.stdout)
        print(f"\n📋 Detected Interface Names: {set(interfaces)}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    find_npcap_interfaces()
