# traffic_filter.py - Smart filtering to reduce false positives

"""
Filters out benign system traffic that causes false positives
WITHOUT retraining the model
"""

# ============================================================================
# WHITELIST CONFIGURATION
# ============================================================================

# Known benign ports (DNS, DHCP, mDNS, NetBIOS, etc.)
BENIGN_PORTS = {
    53,      # DNS
    67, 68,  # DHCP
    137, 138, 139,  # NetBIOS
    5353,    # mDNS (Multicast DNS)
    123,     # NTP (Time sync)
    1900,    # SSDP (UPnP)
    5355,    # LLMNR
}

# Known benign IPs (routers, gateways)
BENIGN_IPS = {
    '192.168.1.1',    # Common router
    '192.168.1.254',  # Your router
    '192.168.0.1',
    '10.0.0.1',
    '127.0.0.1',      # Loopback (unless testing)
}

# Multicast/Broadcast ranges
MULTICAST_RANGES = [
    '224.',   # IPv4 multicast
    '239.',   # IPv4 multicast
    'ff02:',  # IPv6 multicast
]

BROADCAST_IPS = [
    '255.255.255.255',
    '192.168.1.255',
    '0.0.0.0',
]

# ============================================================================
# FILTERING FUNCTIONS
# ============================================================================

def is_benign_system_traffic(flow_info):
    """
    Detect benign system traffic that should NOT be analyzed
    
    Args:
        flow_info (dict): Must contain src_ip, dst_ip, src_port, dst_port, protocol
        
    Returns:
        bool: True if traffic should be SKIPPED
    """
    src_ip = flow_info.get('src_ip', '')
    dst_ip = flow_info.get('dst_ip', '')
    src_port = flow_info.get('src_port', 0)
    dst_port = flow_info.get('dst_port', 0)
    protocol = flow_info.get('protocol', '').upper()
    
    # Rule 1: DNS traffic (port 53)
    if src_port == 53 or dst_port == 53:
        return True  # Skip DNS
    
    # Rule 2: DHCP traffic (ports 67, 68)
    if src_port in [67, 68] or dst_port in [67, 68]:
        return True  # Skip DHCP
    
    # Rule 3: Other benign ports
    if src_port in BENIGN_PORTS or dst_port in BENIGN_PORTS:
        return True  # Skip known benign services
    
    # Rule 4: Multicast traffic
    for prefix in MULTICAST_RANGES:
        if dst_ip.startswith(prefix):
            return True  # Skip multicast
    
    # Rule 5: Broadcast traffic
    if dst_ip in BROADCAST_IPS:
        return True  # Skip broadcast
    
    # Rule 6: Known benign IPs (routers)
    if src_ip in BENIGN_IPS or dst_ip in BENIGN_IPS:
        # Exception: Allow if targeting web ports (potential attack)
        if dst_port not in [80, 443, 8080, 8443]:
            return True  # Skip router traffic except web
    
    # Rule 7: Loopback (unless testing)
    if src_ip == '127.0.0.1' and dst_ip == '127.0.0.1':
        return True  # Skip localhost (enable for testing)
    
    return False  # Analyze this traffic


def post_process_prediction(label, score, flow_info):
    """
    Apply business rules AFTER prediction to fix obvious errors
    
    Args:
        label (str): Predicted attack label
        score (float): Confidence score
        flow_info (dict): Flow metadata
        
    Returns:
        tuple: (corrected_label, corrected_score)
    """
    protocol = flow_info.get('protocol', '').upper()
    src_port = flow_info.get('src_port', 0)
    dst_port = flow_info.get('dst_port', 0)
    packet_count = flow_info.get('packet_count', 0)
    
    # Rule 1: UDP cannot be "Slowhttptest" (HTTP is TCP only!)
    if protocol == 'UDP' and 'Slowhttp' in label:
        return "BENIGN", 0.05
    
    # Rule 2: DNS port 53 is NEVER an HTTP attack
    if (src_port == 53 or dst_port == 53) and ('DoS' in label or 'Slow' in label):
        return "BENIGN", 0.05
    
    # Rule 3: HTTPS (443) with few packets is not DoS
    if dst_port == 443 and packet_count < 20 and 'DoS' in label:
        if score < 0.92:  # Lower threshold
            return "BENIGN", score * 0.3
    
    # Rule 4: Router traffic (192.168.x.254) needs high confidence
    src_ip = flow_info.get('src_ip', '')
    if src_ip.endswith('.254') or src_ip.endswith('.1'):
        if score < 0.95:  # Very high threshold for router
            return "BENIGN", score * 0.5
    
    # Rule 5: FTP/SSH attacks must use correct ports
    if 'FTP-Patator' in label and dst_port != 21:
        return "BENIGN", score * 0.3
    
    if 'SSH-Patator' in label and dst_port != 22:
        return "BENIGN", score * 0.3
    
    # Rule 6: Web attacks must target web ports
    if 'Web Attack' in label:
        if dst_port not in [80, 443, 8080, 8443]:
            return "BENIGN", score * 0.2
    
    # Rule 7: PortScan needs many different ports
    if 'PortScan' in label:
        # TODO: Track unique ports per src_ip
        # For now, require high confidence
        if score < 0.90:
            return "BENIGN", score * 0.4
    
    # Rule 8: Heartbleed must target SSL/TLS port
    if 'Heartbleed' in label and dst_port not in [443, 444, 8443]:
        return "BENIGN", score * 0.1
    
    return label, score  # Keep original prediction


def should_generate_alert(label, score, flow_info, min_score=0.85):
    """
    Decide if an alert should be generated
    
    Args:
        label (str): Attack label
        score (float): Confidence
        flow_info (dict): Flow metadata
        min_score (float): Minimum score threshold
        
    Returns:
        bool: True if alert should be generated
    """
    # Never alert on BENIGN
    if label.upper() == "BENIGN":
        return False
    
    # Check minimum score
    if score < min_score:
        return False
    
    # Additional checks for specific attacks
    if 'DoS' in label or 'DDoS' in label:
        # DoS needs higher packet count
        if flow_info.get('packet_count', 0) < 50:
            return False
    
    if 'PortScan' in label:
        # PortScan should have many connections
        if flow_info.get('packet_count', 0) < 10:
            return False
    
    return True


# ============================================================================
# STATISTICS & MONITORING
# ============================================================================

class TrafficStats:
    """Track filtering statistics"""
    
    def __init__(self):
        self.total_flows = 0
        self.filtered_flows = 0
        self.analyzed_flows = 0
        self.alerts_generated = 0
        self.false_positives_prevented = 0
        
    def record_flow(self, filtered=False):
        self.total_flows += 1
        if filtered:
            self.filtered_flows += 1
        else:
            self.analyzed_flows += 1
    
    def record_alert(self):
        self.alerts_generated += 1
    
    def record_false_positive_prevented(self):
        self.false_positives_prevented += 1
    
    def get_summary(self):
        return {
            'total_flows': self.total_flows,
            'filtered_flows': self.filtered_flows,
            'analyzed_flows': self.analyzed_flows,
            'alerts_generated': self.alerts_generated,
            'false_positives_prevented': self.false_positives_prevented,
            'filter_rate': f"{(self.filtered_flows/max(self.total_flows,1))*100:.1f}%"
        }
    
    def reset(self):
        self.__init__()


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Test cases
    test_flows = [
        {'src_ip': '192.168.1.60', 'dst_ip': '192.168.1.254', 'src_port': 50123, 'dst_port': 53, 'protocol': 'UDP'},
        {'src_ip': '192.168.1.60', 'dst_ip': '8.8.8.8', 'src_port': 50124, 'dst_port': 443, 'protocol': 'TCP'},
        {'src_ip': '192.168.1.60', 'dst_ip': '224.0.0.251', 'src_port': 5353, 'dst_port': 5353, 'protocol': 'UDP'},
    ]
    
    print("Testing traffic filter:")
    for flow in test_flows:
        should_skip = is_benign_system_traffic(flow)
        print(f"  {flow['dst_ip']}:{flow['dst_port']} → Skip: {should_skip}")
    
    print("\nTesting post-processing:")
    test_predictions = [
        ("DoS Slowhttptest", 0.93, {'protocol': 'UDP', 'dst_port': 53, 'src_port': 50000, 'packet_count': 5}),
        ("DoS Hulk", 0.88, {'protocol': 'TCP', 'dst_port': 443, 'src_port': 50001, 'packet_count': 150}),
    ]
    
    for label, score, flow in test_predictions:
        new_label, new_score = post_process_prediction(label, score, flow)
        print(f"  {label} ({score:.2f}) → {new_label} ({new_score:.2f})")