#
# Copyright (c) 2013, Laird Connectivity
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

_EXE  = event_mon
_OBJS = event_mon.o
_LIBS = -lsdc_sdk

%.o: %.c
	$(CXX) $(CFLAGS) -c -Wall $^ -o $@

all: $(_EXE)

$(_EXE): $(_OBJS)
	$(CXX) $(LDFLAGS) -o $(_EXE) $(_OBJS) $(_LIBS)

clean:
	rm -f $(_OBJS) $(_EXE)

.PHONY: clean

