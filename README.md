# 🛰️ Air-Wraith (v1.0-Elite)
**The Autonomous WiFi Stealth Suite for Red Team Operations.**

Air-Wraith is a high-performance WiFi auditing tool designed for penetration testers and security researchers. It automates the process of network discovery, targeted deauthentication, and WPA/WPA2 handshake capturing into a single, sleek terminal interface.



## ✨ Key Features
* **Active Reconnaissance:** Real-time 802.11 Beacon frame sniffing to map surrounding networks.
* **Intelligent Channel Hopping:** Cycles through 2.4GHz channels (1-13) to ensure no target is missed.
* **Handshake Snatcher:** Automated EAPOL (4-Way Handshake) detection and extraction into `.pcap` files.
* **Broadcast & Targeted Deauth:** Disconnect all users or specific targets using localized packet injection.
* **Cyberpunk TUI:** Built with `Rich` library for a professional and highly readable terminal experience.



## 🚀 Installation & Usage

### Prerequisites
* **OS:** Kali Linux, Parrot OS, or any Linux distro.
* **Hardware:** A WiFi adapter supporting **Monitor Mode** and **Packet Injection** (e.g., Alfa AWUS036ACM).

### Setup
```bash
# Clone the repository
git clone [https://github.com/n0merc/air-wraith](https://github.com/n0merc/air-wraith)
cd air-wraith

# Install dependencies
pip3 install -r requirements.txt
Execution
Enable Monitor Mode on your adapter:

Bash
sudo airmon-ng start wlan0
Run Air-Wraith:

Bash
sudo python3 air_wraith.py wlan0mon
```
🛠️ Roadmap
[ ] 5GHz Band Support

[ ] Automated Evil Twin Access Point creation

[ ] Captive Portal integration for credential harvesting

⚖️ Legal Disclaimer
Usage of Air-Wraith for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The author (n0merc) assumes no liability and is not responsible for any misuse or damage caused by this program.
