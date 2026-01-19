/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * logging abstraction
 */

#ifndef __MINIVTUN_LOG_H
#define __MINIVTUN_LOG_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef NO_LOG
    #define LOG(...) do {} while(0)
    #define PLOG(...) do {} while(0)
#else
    #define LOG(fmt, ...) fprintf(stderr, "minivtun: " fmt "\n", ##__VA_ARGS__)
    #define PLOG(fmt, ...) fprintf(stderr, "minivtun: " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))
#endif

#endif /* __MINIVTUN_LOG_H */

