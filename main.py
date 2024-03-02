from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP


arp = ARP(pdst="192.168.1.1/24")

broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = broadcast/arp
res = srp(packet, timeout=3,verbose=0)[0]

for sent, element in res:
    print(f'IP: {element.psrc}, MAC: {element.hwsrc}')