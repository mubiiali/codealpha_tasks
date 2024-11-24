from scapy.all import *

def sniff_packets(pkt):
    print(pkt.summary())

sniff(prn=sniff_packets, filter="tcp")