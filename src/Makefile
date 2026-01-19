#
# Copyright (c) 2015 Justin Liu
# Author: Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/minivtun
#
# Advanced Makefile for modular builds
#

# Customizable Prefix
# ---------------------------------
PREFIX ?= /usr/local

# Build Configuration
# ---------------------------------
# Set to 'yes' to enable features, 'no' to disable
WITH_IPV6          ?= yes
WITH_DAEMONIZE     ?= yes
WITH_CLIENT_MODE   ?= yes
WITH_SERVER_MODE   ?= yes
OPTIMIZE_FOR_SIZE  ?= no
NO_LOG              = no

# Backend Selection
# ---------------------------------
#
# Copyright (c) 2015 Justin Liu
# Author: Justin Liu <rssnsj@gmail.com>
# https://github.com/rssnsj/minivtun
#
# Advanced Makefile for modular builds
#

# Customizable Prefix
# ---------------------------------
PREFIX ?= /usr/local

# Build Configuration
# ---------------------------------
# Set to 'yes' to enable features, 'no' to disable
WITH_IPV6          ?= yes
WITH_DAEMONIZE     ?= yes
WITH_CLIENT_MODE   ?= yes
WITH_SERVER_MODE   ?= yes
OPTIMIZE_FOR_SIZE  ?= no
NO_LOG              = no

# Backend Selection
# ---------------------------------
CRYPTO_BACKEND     ?= openssl
# PLATFORM is auto-detected, but can be overridden (e.g., PLATFORM=linux)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM ?= linux
endif
ifeq ($(UNAME_S),FreeBSD)
    PLATFORM ?= bsd
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM ?= bsd
endif
PLATFORM ?= linux # Default to linux if detection fails

# Compiler and Flags
# ---------------------------------
CC ?= gcc
CFLAGS += -Wall
LDFLAGS ?=

# Feature Flags
# ---------------------------------
CFLAGS += -DWITH_IPV6=$(if $(filter yes,$(WITH_IPV6)),1,0)
CFLAGS += -DWITH_DAEMONIZE=$(if $(filter yes,$(WITH_DAEMONIZE)),1,0)
CFLAGS += -DWITH_CLIENT_MODE=$(if $(filter yes,$(WITH_CLIENT_MODE)),1,0)
CFLAGS += -DWITH_SERVER_MODE=$(if $(filter yes,$(WITH_SERVER_MODE)),1,0)

ifeq ($(NO_LOG),yes)
    CFLAGS += -DNO_LOG=1
endif

# Optimization Flags
# ---------------------------------
ifeq ($(OPTIMIZE_FOR_SIZE),yes)
    CFLAGS += -Os -ffunction-sections -fdata-sections
    LDFLAGS += -Wl,--gc-sections
    STRIP_FLAG = yes
else
    CFLAGS += -g
endif

# Source Files
# ---------------------------------
SRCS = library.o minivtun.o

# Platform sources
SRCS += platform_$(PLATFORM).o

# Feature sources
ifeq ($(WITH_CLIENT_MODE),yes)
    SRCS += client.o
endif
ifeq ($(WITH_SERVER_MODE),yes)
    SRCS += server.o
endif

# Crypto backend sources and libs
ifeq ($(CRYPTO_BACKEND),openssl)
    SRCS += crypto_openssl.o
    LDLIBS += -lcrypto
else
    $(error Unsupported CRYPTO_BACKEND: $(CRYPTO_BACKEND))
endif


HEADERS = minivtun.h library.h list.h jhash.h platform.h crypto_wrapper.h log.h

# Targets
# ---------------------------------
.PHONY: all clean install uninstall

all: minivtun

minivtun: $(SRCS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: minivtun
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 minivtun $(DESTDIR)$(PREFIX)/sbin/
ifeq ($(STRIP_FLAG),yes)
	strip $(DESTDIR)$(PREFIX)/sbin/minivtun
endif

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/minivtun

clean:
	rm -f minivtun *.o


HEADERS = minivtun.h library.h list.h jhash.h platform.h crypto_wrapper.h log.h

# Targets
# ---------------------------------
.PHONY: all clean install uninstall

all: minivtun

minivtun: $(SRCS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: minivtun
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 minivtun $(DESTDIR)$(PREFIX)/sbin/
ifeq ($(STRIP_FLAG),yes)
	strip $(DESTDIR)$(PREFIX)/sbin/minivtun
endif

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/minivtun

clean:
	rm -f minivtun *.o
