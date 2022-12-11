# HCMUTE-CTF Season 1

Bài viết này dùng để write up cho các challenges HCMUTE-CTF mùa 1.

Mỗi challenge mình sẽ đi vào hướng giải quyết trọng tâm để bài viết được ngắn. Khuyến khích nên tự tìm hướng giải quyết trước, cố tìm hiểu thật nhiều cách tiếp cận cho 1 vấn đề, mở suy nghĩ tối đa. Quan điểm của mình là nên tập luyện thật nhiều và tự tạo ra case test hay check list cho mỗi chủ đề, để có cách tiếp cận đầy đủ.

Cảm ơn các bạn đã quan tâm.

### Overview
 | Title                                           | Category    | Flag |
 | :---------------------------------------------- | :---------- | :------ |
 | [impleKeygenV1.1](#SimpleKeygenV11)             | RE          |  |
 | [SimpleKeygenV2.0](#SimpleKeygenV20)            | RE          |  |
 | [EzCr4ckV2](#EzCr4ckV2)                         | RE          |  |
 | [humor laws](#humor-laws)                       | FORENSICS   |  |
 | [Gi_ #%$&](#Gi_-)                               | FORENSICS   |  |
 | [HOHO](#HOHO)                                   | MISC        |  |
 | [Source Code](#Source-Code)                     | WEB         |  |
 | [Web2](#Web2)                                   | WEB         |  |
 | [Web6](#Web6)                                   | WEB         |  |
 | [IPPBX](#IPPBX)                                 | NETWORKING  |  |
 | [Triangle](#Triangle)                           | PROGRAMMING |  |
 | [Bitcoin Address](#Bitcoin-Address)             | CRYPTO      |  |
 | [Exclusive or](#Exclusive-or)                   | CRYPTO      |  |
 | [Welcome to CTF HCMUTE](#Welcome-to-CTF-HCMUTE) | OSINT       |  |

# SimpleKeygenV1.1
# SimpleKeygenV2.0
# EzCr4ckV2
# humor laws

Thử thách cung cấp 1 file pdf. Với chủ đề forensic ta cần tiếp cận bằng cách kiểm tra các thông tin mà file mang trên nó. Một trong những thông tin rà soát cần thiết là `metadata`.

Ta có thể dùng `exiftool` có trên linux hoặc đơn giản hơn truy cập vào trang sau https://exif.tools/.

![image](https://user-images.githubusercontent.com/56266496/206899615-81d8b928-4c9e-455e-8df9-84826beee207.png)

Phát hiện 1 chuỗi mật mã lạ.

![image](https://user-images.githubusercontent.com/56266496/206899712-22e06d37-0fba-4d2a-9bf3-762af9ba67d7.png)

Giải mã base64 ta tìm được flag. Bạn dùng tool nào cũng được, ở đây mình dùng luôn js trên dev tool cho gọn.

# Gi_ #%$&

1 trong những cách tiếp cận 1 file gif là split nó ra.

![image](https://user-images.githubusercontent.com/56266496/206899909-1d3f7a4c-a1b4-43f6-8fff-71a135ce23d8.png)

Ở đây mình dùng https://ezgif.com/split. Thông tin có được là `UTECTF{fL4g_here?}`. Nộp thử thì đây là fake.

Hướng tiếp cận khác là mở rộng size ảnh trường hợp thông tin bị giấu ở phần mở rộng của ảnh. Để làm điều này cần đọc hiểu về cấu trúc file, keyword để research là `file format` hoặc `structure`.

![image](https://user-images.githubusercontent.com/56266496/206900132-6e0dd01b-88a4-4659-9993-8790f3ec8f2a.png)

Theo thông tin đọc được, 1 file GIF có thể chứa nhiều hình ảnh. Ta có thể thay đổi size mỗi ảnh trong gif bằng cách thay đổi 2 block `image width` và `image height`.

Một trong những công cụ dùng thay đổi cấu trúc 1 file là [HxD](https://mh-nexus.de/en/hxd/). Quan sát thi ở vị trí ảnh có nền trắng gần như có phần kéo dào xuống dưới.
Vậy ta thay đổi size ở vị trí ảnh này.

![image](https://user-images.githubusercontent.com/56266496/206900594-5ca9d4ca-7195-4a0e-8819-24c2b100e3dd.png)

Kích thước ban đầu là `A0 00` tức là `0A` = 160. Để kéo dài ta thử tăng lên 500 = `1F4` = `F4 01`.

![image](https://user-images.githubusercontent.com/56266496/206900612-15a251e8-7764-4bb0-8d25-9ff2d9ff10e3.png)

Split gif lần nữa ta thấy được phần còn lại của flag.

# HOHO
# Source Code

Ở thử thách này ta cần `view source` tại trang index của https://ctf.hcmute.edu.vn/.

![image](https://user-images.githubusercontent.com/56266496/206900701-88c959c2-bb4f-46bb-91ca-86973a764fe6.png)

# Web2

View source của web ta tìm được param ẩn gợi ý là `is_debug`.

![image](https://user-images.githubusercontent.com/56266496/206900750-dd522f06-8525-40af-a641-7666b19b941c.png)

Thử GET với param ẩn ta tìm được flag.

![image](https://user-images.githubusercontent.com/56266496/206900797-5226e2f8-57fd-4f12-b0be-54b26ab7b751.png)

# Web6

View source của web ta tìm được param ẩn gợi ý là `is_debug`.

![image](https://user-images.githubusercontent.com/56266496/206900895-759bc9b7-4c2e-4c64-bafe-b20056a473b3.png)

Bật param ẩn ta được source code php của web.

```php
<?php if(isset($_GET['user']) && isset($_GET['pass'])){
$user = new User($_GET['user'],$_GET['pass']);
$user->check();
}?>

<?php
class getFileSystem{
	public function __wakeup(){
		include('flag.php');
		echo $flag;
	}
}
class User{
	public function __construct($u,$p){
	$this->username = $u;
	$this->password = $p;
	}
	public function check(){
		echo "<h3 style=color:red>Something went wrong.</h3>";
	}
	public function __destruct(){
		if ($this->password=="G98xLj4rwr3sx"){
			unserialize(base64_decode($this->username));
		}
	}
}
?>
```

Ta có được một phần php khá thú vị. File `flag.php` sẽ được include vào nếu hàm `__wakeup()` được chạy. Phương thức `__wakeup()` sẽ được gọi khi chúng ta `unserialize()` đối tượng `getFileSystem()`.

![image](https://user-images.githubusercontent.com/56266496/206901351-222d2809-bcfb-41db-8ff7-cc179f2438f6.png)

Ta có thể kiểm tra lại điều này bằng cách thử bằng đoạn code ngắn trên.

Ta có thể dễ dàng control được biến `username` bên trong phương thức unserialize `unserialize(base64_decode($this->username));`.

![image](https://user-images.githubusercontent.com/56266496/206901550-5db04361-eff9-4a63-91e5-51f1845c5e8c.png)

Tạo payload cho biến `username`.

![image](https://user-images.githubusercontent.com/56266496/206901603-85674120-d853-475e-b192-d1dd13d0d61a.png)

Nhập payload và lấy flag.

# IPPBX

Tổng đài điện thoại nội bộ dùng giao thức Internet hay Tổng đài IP (tiếng Anh: Internet Protocol Private Branch eXchange, viết tắt là IP PBX hay IPBX) là một mạng điện thoại riêng dùng giao thức Internet (Internet protocol) để thực hiện các cuộc gọi điện thoại ra bên ngoài, thường áp dụng trong phạm vi một công ty, nhà hàng, hay bệnh viện. Dữ liệu giọng nói được truyền bằng các gói dữ liệu qua Internet thay vì mạng điện thoại thông thường.

![image](https://user-images.githubusercontent.com/56266496/206901845-a7281e76-fdee-4a7e-ac8f-3f7ab4b60fee.png)

Một trong những giao thức được sử dụng trong tổng đài ip là RTP. Vấn đề của RTP là không mã hoá. Bài này flag có thể được nghe qua đoạn ghi âm ngắn.

Để nghe được cần vào `Telephony > RTP > RTP Stream`.

# Triangle

```
Xin chào người chơi.
Bạn có biết tam giác 🛆  là hình rất đặc biệt không? Cùng xem điều đặc biệt đó nhé!
--> Đếm số hình tam giác <--
Có bao nhiêu tam giác được tạo bởi N số (1..N). N < 10^6
Ví dụ: với N = 5
Kết quả sẽ là: 3

(2,3,4),(3,4,5),(2,4,5)
................/\...................|\...................
.............../  \..................| \..................
............../    \.................|  \.................
............./      \................|   \................
............/        \...............|    \...............
.........../          \..............|     \..............
........../____________\.............|______\.............

[+] N = 654
[+] Kết quả: 
```

Đề bài như trên. Thử tính một lúc được dãy số sau: `0 0 1 3 7 13 22 34 50`. Dùng google tìm dãy số này dẫn đến trang sau https://oeis.org/A173196

Công thức để giải bài toàn này là: `(4*n^3 + 6*n^2 - 4*n - 3 + 3*(-1)^n)/48`

```
#!/usr/bin/python3
import socket

IP, PORT = ('115.79.193.109', 28064)

def receive_all_line(s):
    data = s.recv(999999)
    return data.decode()

def receive_one_line(s):
    r = b''
    while (True):
        t = s.recv(1)
        if t == b'\n': break
        r = r + t
    return r.decode()

def send_one_line(s, data):
    s.sendall(f"{data}\n".encode())

def solver(n):
    n -= 2
    return (4*n**3 + 6*n**2 - 4*n - 3 + 3*(-1)**n)//48

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))

    for i in range(16):
        banner = receive_one_line(s)
        print(banner)
    while True:
        banner = receive_one_line(s)
        print(banner)
        n = int(banner[8:])
        answer = solver(n)
        send_one_line(s, answer)
        print(answer)
        banner = receive_one_line(s)

    s.close()

if __name__ == '__main__':
    main()
```

Chương trình dùng giải programming này như trên.

![image](https://user-images.githubusercontent.com/56266496/206903675-8ae6368b-c1e9-4d31-ae53-4aa5ddd37026.png)

# Bitcoin Address

![image](https://user-images.githubusercontent.com/56266496/206903708-0be07f06-4666-48a1-be70-a6dcf8e691fc.png)

Giải mật mã base58 tìm được flag. Trang mình dùng để giải là https://gchq.github.io/CyberChef/.

# Exclusive or

```
flag = ###SECRET###
key = ###SECRET###
assert len(key) == 1

def encrypt(a,b):
    return ''.join([hex(ord(b[i%len(b)]) ^ ord(a[i]))[2:] for i in range(0,len(a))])

with open('cipher.txt', 'w') as f:
	f.write(encrypt(flag, key))
```

Chương trình dùng để tạo mã như trên.

`ord(b[i%len(b)])` có thể viết lại là `ord(b[0])` do `len(key) == 1`

`ord(b[0]) ^ ord(a[i])` là xor mỗi ký tự flag với key

`hex(ord(b[0]) ^ ord(a[i]))[2:]` là kết quả phép tính xor đem hex rồi bỏ 2 ký tự đầu `0x`

![image](https://user-images.githubusercontent.com/56266496/206903972-d569aa76-a63f-4034-96ba-79cdb98e26d2.png)

Do độ dài key chỉ có 1, dễ dàng brute force. Sử dụng trang sau https://www.dcode.fr/xor-cipher

![image](https://user-images.githubusercontent.com/56266496/206904340-13b3cc15-8281-4df7-b72e-bd0ebd9fa8cd.png)

Tìm được flag.

# Welcome to CTF HCMUTE

Truy cập link discord là có được flag. https://discord.gg/au2XEJ9J6B
