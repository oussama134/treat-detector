# capture_with_tshark.py
import subprocess
import shutil
import sys
import os

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"  # or path to tshark

def capture(duration=10, iface_index=4, out_path="data/live_traffic.pcap"):
    # iface_index: 1-based index from `tshark -D` output; or pass a name
    if not os.path.exists(os.path.dirname(out_path)):
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
    cmd = [TSHARK, "-a", f"duration:{duration}", "-w", out_path]
    # optionally pick interface by "-i <index>"
    if iface_index is not None:
        cmd = [TSHARK, "-i", str(iface_index), "-a", f"duration:{duration}", "-w", out_path]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print("Captured to", out_path)
