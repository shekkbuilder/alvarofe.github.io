---
author: alvaro
comments: true
date: 2009-06-30 15:14:29+00:00
layout: post
slug: formatshield
title: 'FormatShield: A tool to defend against format string attacks'
description: 'FormatShield: Download formatshield source'
wordpress_id: 291
categories:
- Archive
tags:
- binary rewriting
- format string attacks
- formatshield
- memory corruption attacks
---


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
```