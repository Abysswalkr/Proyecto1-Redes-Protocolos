# propósito: generar un PCAP mínimo de SYN a puertos 20..30
from scapy.all import IP, TCP, wrpcap
pkts = [IP(dst="192.0.2.1")/TCP(dport=p, flags="S") for p in range(20, 31)]
wrpcap("servers/porthunter/samples/nmap_syn_scan.pcap", pkts)
print("OK: servers/porthunter/samples/nmap_syn_scan.pcap")
