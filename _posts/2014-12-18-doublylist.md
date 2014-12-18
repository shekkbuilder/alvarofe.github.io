---
author: alvaro
comments: true
layout: post
title: How Linux Implements Generic List
categories:
- Archive
tags:
- security
---

I was reading [Understanding the Linux Kernel](http://shop.oreilly.com/product/9780596005658.do) about how each process is represented through `task_struct` and so on. The kernel uses a lot of struct to represent different kind of data and it uses lists to manage relationship between them. It would be a waste of time that for each kind of struct was necessary develop a new list, functions to handle it … etc. To resolve this, Linux makes use of a generic list. The idea is as follows.

![linked-list](/public/images/linked-list.png)

If you want that your struct be in a list all what you have to do is include a `list_head` inside it. `list_head` is defined as follows (I am using the source code of Linux 2.6.0).

```C
struct list_head {
	struct list_head *next, *prev;
};
```

Where `next` and `prev` point to the next and previous element in the list respectively. The first question that has came to me is how are we able to get the pointer to the real struct if we only have a pointer to `list_head`?. The solution provided by Linux is very clever. Before to know is better to have better context about a real struct used by Linux as `task_struct`.

```C
struct task_struct {
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	struct thread_info *thread_info;
	atomic_t usage;
	unsigned long flags;	/* per process flags, defined below */
	unsigned long ptrace;

	int lock_depth;		/* Lock depth */

	int prio, static_prio;
	struct list_head run_list;
	prio_array_t *array;

	unsigned long sleep_avg;
	long interactive_credit;
	unsigned long long timestamp;
	int activated;

	unsigned long policy;
	cpumask_t cpus_allowed;
	unsigned int time_slice, first_time_slice;

	struct list_head tasks;

	/* there are more types*/
  . . .
}
```

You can see how inside the `task_struct` has a member whose name is `task` of type `list_head`. This is used to track each process that run inside the kernel so through this member we can  retrieve all the process. There is a macro inside the Linux Kernel to run through all the process.

```C

#define next_task(p)	list_entry((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

```

In `list_entry` is where we are going to get in this case the pointer to `task_struct`.

```C
/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})
```

The magic really happens in `container_of` and is really simple. The first line declares `__mptr` equal to the type of the `member` inside the `type` and is assigned `ptr` that in our case would be `task` of the actual process. The second line   subtract the address of `__mptr` the offset between the `task_struct` and the member `task`, thanks to that you are able to get a reference to the `task_struct` through `task`.

Maybe is a little bit confusing at the beginning but once you get used to it, is very useful since you can apply the same idea to your projects. You should check this out [/include/linux/list.h](https://github.com/torvalds/linux/blob/master/include/linux/list.h) and seeing the rest of the functions that Linux uses to manipulate list.

 
{% include twitter_plug.html %}