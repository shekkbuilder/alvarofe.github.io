---
author: alvaro
comments: true
layout: post
title: Defeating qcrk5 crackme
categories:
- Archive
tags:
- security
---

Today I am going to write up about how I resolved this [crackme](http://crackmes.de/users/qnix/qcrk5/). The level of this crackme is easy so it should not be difficult for those with the minimum of knowledge about reversing. This crackme like the majority of them ask for a password that we have to extract it, to bypass the check and win the flag.

The first task when we face against these challenges is to know the maximum about the binary. Basically the gather information phase.

```bash
➜  crackmes  file qcrk5
qcrk5: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.4.1, stripped
```

It is a ELF-binary and is statically linked. So far, so good. Now we run strace to look for example what kind of syscall is doing.

```c
➜  crackmes  strace ./qcrk5 1234
execve("./qcrk5", ["./qcrk5", "1234"], [/* 34 vars */]) = 0
[ Process PID=3869 runs in 32 bit mode. ]
uname({sys="Linux", node="alvaro-debian", ...}) = 0
brk(0)                                  = 0x87fe000
brk(0x881f000)                          = 0x881f000
open("/dev/urandom", O_RDONLY)          = 3
read(3, "\277Y\307X", 4)                = 4
close(3)                                = 0
ptrace(PTRACE_TRACEME, 0, 0x1, 0)       = -1 EPERM (Operation not permitted)
exit_group(1)                           = ?
```

It has anti-debugging trick embedded inside the program. So is presumably that when we run the binary using gdb the same thing happens.

```
gdb-peda$ r 1234
[Inferior 1 (process 3939) exited with code 01]
```

But with gdb we can bypass the ptrace syscall always returning the good value and that can be achieved writting in .gdbinit the following.

```
catch syscall ptrace
commands 1
set ($eax) = 0
continue
end
```

Basically we are going to set up a [catchpoint](https://sourceware.org/gdb/current/onlinedocs/gdb/Set-Catchpoints.html#Set-Catchpoints) each time that ptrace is called. Then using `commands 1` we are saying that each time that the breakpoint with value 1 (that is gonna be the catchpoint) is hit, we set `eax` to 0 and then continue the execution. Basically each time that ptrace is called is gonna return 0. Thanks to that, we are going to bypass the ptrace check and it lets us debug our binary. We could also bypass the ptrace check using `LD_PRELOAD` hooking a ptrace call and so on but this one is more easy and quickly to accomplish.

```
gdb-peda$ r 1234

Catchpoint 1 (returned from syscall ptrace), 0x0804ea76 in ?? ()
Using 1234
Wrong!
[Inferior 1 (process 4011) exited normally]
```

It's time to dive in the binary to know what is going on in the main function. You can use either radare2 or Hopper to resolve it. I am going to use both. 

```
➜  crackmes  r2 qcrk5
 -- bash: r3: command not found
[0x08048110]> aa
Function too big at 0x809824c
[0x08048110]> afl
0x08048110  34  1  entry0
0x08048340  753  45  fcn.08048340
...
0x080503a3  235  19  fcn.080503a3
0x08048134  33  3  fcn.08048134
0x08048160  68  8  fcn.08048160
0x080481a4  99  6  fcn.080481a4
0x08048208  306  8  main
```
The main function is located at `0x08048208` so let's go ahead and disassemble it.

```
[0x08048110]> pdf@main
/ (fcn) main 306
|          ; var int local_8 @ ebp-0x8
|          ; var int local_4 @ ebp-0x4
|          ; var int local_14 @ ebp-0x14
|          ; arg int arg_4b7f3da0 @ ebp+0x4b7f3da0
|          ; arg int arg_8 @ ebp+0x8
|          ; arg int arg_c @ ebp+0xc
|          ; DATA XREF from 0x08048127 (entry0)
|          ; DATA XREF from 0x00000127 (fcn.0000010b)
|          ;-- main:
|          0x08048208    55           push ebp
|          0x08048209    89e5         mov ebp, esp
|          0x0804820b    83ec28       sub esp, 0x28
|          0x0804820e    83e4f0       and esp, 0xfffffff0
|          0x08048211    b800000000   mov eax, 0
|          0x08048216    83c00f       add eax, 0xf
|          0x08048219    83c00f       add eax, 0xf

...

```

The output is quite long and I am not going to write it. But for example in `0x0804824a` it calls a function passing four paramaters `0,0,1,0` and if `eax` is less than 0 the function returns. This is basically the ptrace call that stop us to debug the binary. Now I am going to use Hopper since it provides a decompiler that make the work easier for us.

```c
int main(int arg0, int arg1, int arg2) {
    esp = (esp & 0xfffffff0) - (0x1e >> 0x4 << 0x4);
    var_4 = 0x4b7f3da0;
    if (sub_804ea50(0x0, 0x0, 0x1, 0x0) < 0x0) {
            var_14 = 0x1;
    }
    else {
            if (arg_0 != 0x2) {
                    eax = *arg_4;
                    sub_8049530(*0x80af3b4, "Usage : %s <password>\n", eax);
                    sub_8048c10(0x0);
            }
            var_8 = sub_08048b30();
            *var_8 = *var_8 + 0x5;
            *var_8 = *var_8 + 0x60;
            var_8 = (var_8 << 0x8) - var_8;
            var_8 = var_8 * 0x909090;
            eax = *(arg_4 + 0x4);
            sub_8049530(*0x80af3b4, "Using %s\n", eax);
            if (var_4 == var_8) {
                    eax = *0x80af3b4;
                    sub_8049530(STK33, eax, "Correct, Cracked !!\n");
                    sub_8048c10(0x0);
            }
            eax = *0x80af3b4;
            sub_8049530(STK33, eax, "Wrong!\n");
            sub_8048c10(0x0);
    }
    eax = var_14;
    return eax;
}


```

We have to achieve that `var_8` be equal to `0x4b7f3da0`. We should know what returns `sub_08048b30()`. To know that, our best friend as always is gdb.

```
gdb-peda$ b *0x08048208
Breakpoint 2 at 0x8048208
gdb-peda$ r 16

/******  
0x804829c:   call   0x8048be0
0x80482a1:   mov    DWORD PTR [ebp-0x8],eax
*******/
gdb-peda$ b *0x80482a1
Breakpoint 3 at 0x80482a1
gdb-peda$ c
gdb-peda$ p $eax
$1 = 0x10
```

So `var_8` is equal to argv[1]. `sub_08048b30()` must be `atoi` or other similar function.

```C
#include<stdio.h>

int main(int argc, char **argv)
{
  unsigned int var8,temp,i;

  for (i = 0; i < 0xffffffff; i++)
  {
    var8 = i + 0x5;
    var8 = var8 + 0x60;
    temp = var8;
    var8 = ( var8 << 0x8) - temp;
    var8 = var8 * 0x909090;
    if( var8 == 0x4b7f3da0){
      printf("Key found %u\n", i);
      return(0);
    }
  }
}
```

```
➜  /tmp  make pass
cc     pass.c   -o pass
➜  /tmp  ./pass
Key found 91867153
➜  crackmes  ./qcrk5  91867153
Using 91867153
Correct, Cracked !!
```

{% include twitter_plug.html %}
