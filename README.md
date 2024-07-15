# Wifi-Deauther
Linux script to perform a deauth attack on multiple targets

## Overview

The Deauther Tool is a Python script designed to perform Wi-Fi deauthentication attacks. It allows users to scan for available networks and stations, then send deauthentication packets to disrupt connections. This tool is intended for security testing purposes only.

## Features

- Scan for available Wi-Fi networks and connected stations.
- Send deauthentication packets to target networks or stations.
- Configurable via an INI file.
- Logging of all activities.
- GUI for ease of use.

## Requirements

- Python 3.x
- Scapy
- Tkinter
- Root or administrative privileges (for network interface manipulation)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/isertkaya/Wifi-Deauther).git
   cd Wifi-Deauther
   ```

3. **Ensure you have the necessary permissions:**
   - The script requires root or administrative privileges to manipulate network interfaces and send deauthentication packets.

## Configuration

The tool uses a configuration file `deauther_config.ini` to store settings. If this file does not exist, it will be created with default values.

### Default Configuration:
```ini
[DEFAULT]
interface = wlan0
channels = 1-13
deauth_packet_count = 100
```

- **interface:** The network interface to use for scanning and deauthentication.
- **channels:** The range of Wi-Fi channels to scan.
- **deauth_packet_count:** Number of deauthentication packets to send.

## Usage

### Running the Script

1. **Execute the script:**
   ```bash
   sudo python3 deauther.py
   ```

2. **Graphical User Interface:**
   - Upon running, a GUI will appear allowing you to start scanning for networks and stations.

3. **Command Line Interface:**
   - The script can also be run and controlled via the command line. Modify the configuration file as needed and execute the script.

### Example

1. **Start the script:**
   ```bash
   sudo python3 deauther.py
   ```

2. **Scan for networks:**
   - Use the GUI to start scanning for available Wi-Fi networks.

3. **Send deauthentication packets:**
   - Select the target network or station from the GUI and start the deauthentication attack.

## Logging

All activities are logged to `wifi_deauth.log` for auditing and review purposes. Ensure to review this log file regularly to monitor the tool's activity.

## Legal Disclaimer

This tool is intended for educational and security testing purposes only. Unauthorized use of this tool to disrupt networks without permission is illegal. Use responsibly and only on networks you own or have explicit permission to test.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
