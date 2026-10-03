import os
import re
import csv
import sys
import time
import json
import datetime

# Load tabulate if available, else use plain text fallback
try:
    from tabulate import tabulate as _tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# App metadata
APP_NAME    = "CALL AND SIGNAL TRACKER"
APP_VERSION = "1.0"
AUTHOR      = "SWADHIN"
DESCRIPTION = "Analyse your own call logs and mobile network signal strength."

# Directory and file paths
DATA_DIR   = "data"
REPORT_DIR = "reports"
DATA_FILE  = os.path.join(DATA_DIR, "call_data.csv")

# Create directories if they don't exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


# Display the main menu
def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print('=' * 60)
    print(f"  {APP_NAME}  v{APP_VERSION}")
    print(f"  By {AUTHOR}")
    print('=' * 60)
    print("  1. Import data  (CSV / JSON)")
    print("  2. View all logs")
    print("  3. Analyse signal strength")
    print("  4. Export reports (CSV)")
    print('-' * 60)


# Get all network interfaces except loopback
def get_wifi_interface():
    sys_net_path = '/sys/class/net'
    if not os.path.exists(sys_net_path):
        return []
    interfaces = []
    for iface in os.listdir(sys_net_path):
        if iface != 'lo':
            interfaces.append(iface)
    return interfaces


# Scan nearby Wi-Fi networks using iwlist
def scan_wifi(interface, timeout=5):
    networks = []
    print(f"[*] Scanning on '{interface}' — please wait {timeout}s ...")
    os.system(f"iwlist {interface} scan | tee scan_output.txt")
    time.sleep(timeout)
    try:
        with open('scan_output.txt', 'r', errors='ignore') as fh:
            raw = fh.read()
    except FileNotFoundError:
        print("[!] scan_output.txt not found — scan may have failed.")
        return networks
    # Each 'Cell' block represents one access point
    cells = raw.split('Cell')
    for cell in cells:
        if 'ESSID:' in cell:
            network = parse_network_info(cell)
            if network:
                networks.append(network)
    return networks


# Parse one iwlist cell block into a dictionary
def parse_network_info(cell):
    network = {}

    # Helper to extract a regex group or return 'N/A'
    def _extract(pattern, text, group=1):
        match = re.search(pattern, text)
        return match.group(group) if match else 'N/A'

    network["BSSID"]      = _extract(r'Address:\s*([0-9A-Fa-f:]{17})', cell)
    network["SSID"]       = _extract(r'ESSID:"(.*)"', cell)
    network["Channel"]    = _extract(r'Channel:(\d+)', cell)
    network["Frequency"]  = _extract(r'Frequency:([\d\.]+)\s*GHz', cell)
    network["Quality"]    = _extract(r'Quality=(\d+/\d+)', cell)
    network["Encryption"] = detect_encryption(cell)
    network["Signal"]     = _quality_to_percent(network["Quality"])
    return network


# Convert '70/100' quality string to an integer percentage
def _quality_to_percent(quality_str):
    try:
        parts = quality_str.split('/')
        numerator, denominator = int(parts[0]), int(parts[1])
        return int((numerator / denominator) * 100)
    except (ValueError, IndexError, ZeroDivisionError):
        return 0


# Detect encryption type from raw cell text
def detect_encryption(cell):
    if 'WPA3' in cell:
        return 'WPA3'
    elif 'WPA2' in cell:
        return 'WPA2'
    elif 'WPA' in cell:
        return 'WPA'
    elif 'Privacy' in cell:
        return 'WEP'
    else:
        return 'OPEN'


# Add Quality (%) to each network based on dBm signal value
def analyze_signal(networks):
    for net in networks:
        try:
            raw_signal = str(net.get('Signal', '-100'))
            signal_dbm = int(raw_signal.replace('dBm', '').strip())
            quality = max(0, min(100, 2 * (signal_dbm + 100)))
            net['Quality (%)'] = quality
        except (ValueError, AttributeError):
            net['Quality (%)'] = 0
    return networks


# Count how many networks are on each channel
def analyze_channels(networks):
    channel_count = {}
    for net in networks:
        channel = net.get('Channel', 'N/A')
        channel_count[channel] = channel_count.get(channel, 0) + 1
    return channel_count


# Filter networks by security type, SSID name, or minimum quality
def filter_networks(networks, security=None, ssid=None, min_quality=0):
    filtered = []
    for net in networks:
        if security and net.get('Encryption', '') != security:
            continue
        if ssid and ssid.lower() not in net.get('SSID', '').lower():
            continue
        if int(net.get('Quality (%)', 0)) < min_quality:
            continue
        filtered.append(net)
    return filtered


# Return a security label based on the encryption type
def assess_security(network):
    enc = network.get('Encryption', '').upper()
    if 'WPA3' in enc:
        return 'SECURE (WPA3)'
    elif 'WPA2' in enc:
        return 'GOOD (WPA2)'
    elif 'WPA' in enc:
        return 'MODERATE (WPA)'
    elif 'WEP' in enc:
        return 'WEAK (WEP)'
    elif enc in ('OPEN', ''):
        return 'UNSECURED (OPEN)'
    else:
        return 'UNKNOWN'


# Print scan results as a formatted table
def display_result(networks):
    if not networks:
        print("[!] No networks found to display.")
        return
    headers = ["#", "ESSID", "BSSID", "Ch", "Enc", "Signal (%)", "Quality (%)"]
    print("-" * 100)
    print(
        f"{headers[0]:<3} {headers[1]:<25} {headers[2]:<20} "
        f"{headers[3]:<4} {headers[4]:<12} {headers[5]:<11} {headers[6]:<10}"
    )
    print("-" * 100)
    for i, net in enumerate(networks, start=1):
        print(
            f"{i:<3} "
            f"{net.get('SSID', ''):<25} "
            f"{net.get('BSSID', ''):<20} "
            f"{net.get('Channel', ''):<4} "
            f"{net.get('Encryption', ''):<12} "
            f"{net.get('Signal', ''):<11} "
            f"{net.get('Quality (%)', ''):<10}"
        )


# Build a 2D list report with security assessment per network
def generate_report(networks):
    report = [['No', 'SSID', 'BSSID', 'Channel', 'Signal (%)', 'Encryption', 'Security Level']]
    for i, net in enumerate(networks, start=1):
        report.append([
            i,
            net.get('SSID', ''),
            net.get('BSSID', ''),
            net.get('Channel', ''),
            net.get('Quality (%)', ''),
            net.get('Encryption', ''),
            assess_security(net),
        ])
    return report


# Print the security report using tabulate or plain text
def print_report(report):
    print('\n' + '=' * 60)
    print('  WIFI SECURITY ASSESSMENT REPORT')
    print('=' * 60)
    if HAS_TABULATE:
        print(_tabulate(report, headers='firstrow', tablefmt='grid'))
    else:
        print("[!] Install 'tabulate' for a prettier table: pip install tabulate\n")
        header, *rows = report
        print("  ".join(str(h) for h in header))
        print("-" * 80)
        for row in rows:
            print("  ".join(str(cell) for cell in row))


# Save network list to a CSV file
def save_to_csv(networks, filename='wifi_result.csv'):
    if not networks:
        print('[!] No data to save.')
        return
    fields = ['SSID', 'BSSID', 'Channel', 'Encryption', 'Signal', 'Quality (%)', 'Security Level']
    with open(filename, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for net in networks:
            writer.writerow({field: net.get(field, '') for field in fields})
    print(f'[+] Data exported to {filename}')


# Export network list to a JSON file
def export_to_json(networks, filename='wifi_result.json'):
    if not networks:
        print('[-] No data to export.')
        return
    with open(filename, 'w') as fh:
        json.dump(networks, fh, indent=4)
    print(f'[+] Data exported to {filename}')


# Save the report rows to a CSV file
def save_report(report, filename='wifi_report.csv'):
    with open(filename, 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerows(report)
    print(f'[+] Report saved to {filename}')


# Main program flow
def main():
    show_menu()
    interfaces = get_wifi_interface()
    if not interfaces:
        print('[-] No Wi-Fi interfaces found. Enable monitor mode and try again.')
        return
    networks = scan_wifi(interfaces[0], timeout=10)
    if not networks:
        print('[!] Scan returned no results.')
        return
    analyze_signal(networks)
    report = generate_report(networks)
    print_report(report)
    display_result(networks)
    choice = input("\nExport results? (y/n): ").strip().lower()
    if choice == 'y':
        fmt = input("Format (csv / json): ").strip().lower()
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        if fmt == 'csv':
            save_to_csv(networks, filename=os.path.join(REPORT_DIR, f'scan_{timestamp}.csv'))
            save_report(report, filename=os.path.join(REPORT_DIR, f'report_{timestamp}.csv'))
        elif fmt == 'json':
            export_to_json(networks, filename=os.path.join(REPORT_DIR, f'scan_{timestamp}.json'))
        else:
            print('[!] Unknown format. Please enter "csv" or "json".')
    print("\n[+] Scan completed. Stay secure!\n")


if __name__ == "__main__":
    main()
