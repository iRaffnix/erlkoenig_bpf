PROJECT_ROOT = $(shell cd .. && pwd)
UBPF_INC = $(PROJECT_ROOT)/third-party/lib/include
UBPF_LIB = $(PROJECT_ROOT)/third-party/lib/lib

CC ?= gcc
CFLAGS = -O2 -Wall -Wextra -Wpedantic -I$(UBPF_INC)
LDFLAGS = -L$(UBPF_LIB) -lubpf -lm -lstdc++

all: ../priv/ubpf_port

../priv/ubpf_port: ubpf_port.c ubpf_maps.c ubpf_maps.h
	@mkdir -p ../priv
	$(CC) $(CFLAGS) -o $@ ubpf_port.c ubpf_maps.c $(LDFLAGS)

clean:
	rm -f ../priv/ubpf_port

.PHONY: all clean
