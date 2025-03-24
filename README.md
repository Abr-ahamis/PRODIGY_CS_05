# PRODIGY_CS_05
# Network.py

**Network.py** is a Python-based network security tool designed to perform packet sniffing and Address Resolution Protocol (ARP) spoofing. It enables users to monitor network traffic and manipulate ARP tables to intercept communications between devices on a local network.

## Features

- **Packet Sniffing**: Capture and analyze network packets in real-time.
- **ARP Spoofing**: Impersonate devices on the network to intercept and monitor communications.
- **Combined Operations**: Execute both sniffing and ARP spoofing concurrently for comprehensive network analysis.

## Prerequisites

Ensure you have the following installed:

- Python 3.x
- Required Python packages (listed in `requirements.txt`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/network.py.git
   ```

2. Navigate to the project directory:

   ```bash
   cd network.py
   ```

3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running Sniffing and ARP Spoofing Concurrently

To execute both sniffing and ARP spoofing simultaneously for a specific IP address, use the following command:

```bash
sudo python3 network.py ss -i <target_ip>
```

Replace `<target_ip>` with the IP address of the target device. For example:

```bash
sudo python3 network.py ss -i 192.168.0.5
```

### Analyzing Captured Packets

To analyze the captured packets and filter traffic for a specific IP address, use:

```bash
sudo python3 network.py -a <packet_log> -i <target_ip>
```

Replace `<packet_log>` with the path to your packet log file and `<target_ip>` with the IP address you wish to filter. For example:

```bash
sudo python3 network.py -a packet_log.txt -i 192.168.0.5
```

## Command-Line Arguments

- `ss`: Initiates both sniffing and ARP spoofing.
- `-i, --ip`: Specifies the target IP address.
- `-a, --analyze`: Analyzes the specified packet log file.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

**Warning**: This tool is intended for educational and authorized testing purposes only. 

---
