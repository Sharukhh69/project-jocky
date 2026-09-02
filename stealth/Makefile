# Makefile for JOCKY Linux Stealth Modules
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

TARGETS = linux_unhook linux_process_hollow linux_direct_syscalls linux_memfd_exec

all: $(TARGETS)

linux_unhook: linux_unhook.c
	$(CC) $(CFLAGS) $< -o $@ -ldl

linux_process_hollow: linux_process_hollow.c
	$(CC) $(CFLAGS) $< -o $@

linux_direct_syscalls: linux_direct_syscalls.c
	$(CC) $(CFLAGS) $< -o $@

linux_memfd_exec: linux_memfd_exec.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
