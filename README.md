# Packet-Sniffer
This script captures network packets on the local machine using a raw socket, parses the IP headers, and counts the occurrences of unique packet combinations (source IP, destination IP, and protocol). It displays the results in a table using PrettyTable and handles up to 10,000 packets or until interrupted.
