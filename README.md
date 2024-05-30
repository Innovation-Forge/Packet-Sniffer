# Packet Sniffer Script

## Introduction

The Packet Sniffer Script captures network packets on the local machine using a raw socket, parses the IP headers, and counts the occurrences of unique packet combinations (source IP, destination IP, and protocol). It displays the results in a table using PrettyTable. This script is useful for network monitoring, analyzing traffic patterns, and understanding network protocols.

## Features

- **Packet Capture**: Captures network packets using a raw socket.
- **IP Header Parsing**: Parses IP headers to extract source and destination IP addresses, protocol, and other fields.
- **Protocol Mapping**: Maps protocol numbers to their names (e.g., ICMP, TCP, UDP).
- **Packet Counting**: Counts the occurrences of unique packet combinations.
- **Tabular Display**: Displays the results in a sorted table using PrettyTable.
- **Promiscuous Mode**: Enables promiscuous mode to capture all packets on the network interface.

## Prerequisites

- Python 3.6 or higher.
- Administrative or root privileges to create raw sockets and enable promiscuous mode.
- Required Python libraries: `socket`, `ipaddress`, `struct`, `prettytable`.

## Modules

- **socket**: Provides low-level networking interface.
- **ipaddress**: Handles IP addresses.
- **struct**: For packing and unpacking byte data.
- **prettytable**: For displaying tabular data in the console.

```python
import socket
import ipaddress
import struct
from prettytable import PrettyTable
```

## Classes

### `IP`

Represents and parses IP headers.

- **Initialization**: Takes a buffer (packet data) and parses the IP header fields.
- **Attributes**: Version, header length, type of service, total length, identification, fragment offset, time to live, protocol, checksum, source IP, and destination IP.
- **Protocol Map**: A dictionary mapping protocol numbers to their names.

#### Example

```python
class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
```

## Functions

### `main()`

Captures and processes network packets.

- **Sets Socket Protocol**: Sets the protocol for the socket to IP.
- **Creates Raw Socket**: Creates a raw socket and binds it to the host.
- **Enables Promiscuous Mode**: Enables promiscuous mode to capture all packets.
- **Packet Capture Loop**: Captures packets, parses the IP header, and counts unique packet combinations.
- **Displays Results**: Displays the captured packet data in a sorted table using PrettyTable.
- **Disables Promiscuous Mode**: Disables promiscuous mode before exiting.

#### Example

```python
def main():
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    captureDict = {}
    packet_count = 0

    try:
        while True:
            packet = sniffer.recvfrom(65565)
            packet_count += 1
            basePacket = packet[0]
            pckHeader = basePacket[0:20]
            ipOBJ = IP(pckHeader)
            protocolName = ipOBJ.protocol_map.get(ipOBJ.protocol_num, "Unknown")
            packetKey = (str(ipOBJ.src_address), str(ipOBJ.dst_address), protocolName)
            captureDict[packetKey] = captureDict.get(packetKey, 0) + 1

            if packet_count >= 10000:
                print("Processed 10,000 packets.")
                break

    except KeyboardInterrupt:
        pass

    tbl = PrettyTable(["Occurs", "SRC", "DST", "Protocol"])
    for key, value in captureDict.items():
        tbl.add_row([value, key[0], key[1], key[2]])
    print(tbl.get_string(sortby="Occurs", reversesort=True))

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
```

## Usage

1. **Ensure Root/Administrative Privileges**: Make sure you have the necessary privileges to create raw sockets and enable promiscuous mode.

2. **Set Hostname and IP**: The script automatically resolves the current machine's hostname and IP address.

    ```python
    hostname = socket.gethostname()
    HOST = socket.gethostbyname(hostname)
    ```

3. **Run the Script**: Execute the script in your Python environment with the necessary privileges.

    ```bash
    sudo python script_name.py  # For Unix/Linux
    python script_name.py       # For Windows (run as Administrator)
    ```

4. **Monitor the Output**: The script will capture and process up to 10,000 packets, then display the results in a sorted table.

## Example Output

When the script successfully captures and processes packets, the output will be similar to:

```plaintext
+--------+-----------+-----------+----------+
| Occurs | SRC       | DST       | Protocol |
+--------+-----------+-----------+----------+
| 1000   | 192.168.1.1 | 192.168.1.2 | TCP      |
| 500    | 192.168.1.3 | 192.168.1.4 | UDP      |
...
+--------+-----------+-----------+----------+
```

## Error Handling

- **Permission Errors**: Ensure you have the necessary privileges to create raw sockets and enable promiscuous mode.
- **Packet Parsing Errors**: The script gracefully handles errors during packet parsing and continues processing.

## Security Considerations

- **Sensitive Data**: Capturing network packets may expose sensitive data. Ensure you have authorization to monitor network traffic.
- **Promiscuous Mode**: Use promiscuous mode responsibly, as it can capture all network traffic on the interface.

## FAQs

**Q: What happens if the script is run without root/administrative privileges?**
A: The script will fail to create a raw socket and enable promiscuous mode, resulting in an error.

**Q: Can the script capture packets on specific interfaces?**
A: The script is currently set to capture packets on the default network interface. It can be modified to specify a different interface if needed.

**Q: How can I modify the packet capture limit?**
A: Change the `packet_count` condition in the capture loop to adjust the packet capture limit.

## Troubleshooting

- **Permission Issues**: Ensure you run the script with the necessary privileges.
- **Module Not Found Errors**: Ensure Python is installed correctly and all necessary modules are available. Install any missing modules using `pip`.

For further assistance or to report bugs, please reach out to the repository maintainers or open an issue on the project's issue tracker.
