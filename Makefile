#
# Copyright (c) 2013, Laird
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#--------------------------------------------------------------------------

# Set LRD_BUILDROOT_OUTPUT to point to the outout directory of buildroot
# Buildroot must be fully built.
# LRD_BUILDROOT_OUTPUT = /.../wb/buildroot/output/product

CC = arm-sdc-linux-gnueabi-gcc
IDIR = -I$(LRD_BUILDROOT_OUTPUT)/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include -I../../include
LDIR = -L$(LRD_BUILDROOT_OUTPUT)/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/lib

CFLAGS = -c -Wall $(IDIR)

_EXE  = event_mon
_OBJS = event_mon.o
_LIBS = -lsdc_sdk -lpthread -lnl-3 -lnl-genl-3

%.o: %.c
	$(CC) $(CFLAGS) $^ -o $@

all: $(_EXE) $(_EXE_INJ)

$(_EXE): $(_OBJS)
	$(CC) -o $(_EXE) $(_OBJS) $(LDIR) $(_LIBS)

clean:
	rm -f $(_OBJS) $(_EXE) $(_OBJS_INJ)

.PHONY: clean

