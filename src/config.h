#ifndef CONFIG_H
#define CONFIG_H

//根据编译器内置的针对系统的宏去定义宏
//1.如果是FreeBSD和Mac系统就动议HAVE_KQUEUE
#if defined(__FreeBSD__) || defined(__APPLE__)
#define HAVE_KQUEUE
//2. 如果是Linux 就定义HAVE_EPOlL
#elif defined(__linux__)
#define HAVE_EPOLL
//3. 如果是Solaris,就定义HAVE_EVPORT,还引入对应的头文件
#elif defined (__sun)
#define HAVE_EVPORT
#define _XPG6
#define __EXTENSIONS__
#include <stropts.h>
#include <sys/filio.h>
#include <sys/time.h>
#endif

#endif /* CONFIG_H */
