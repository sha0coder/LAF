#!/bin/sh

SYSADDR=$(grep ia32_sys_call_table /boot/System.map-`uname -r` | cut -d ' ' -f 1)
echo "#define SYSCALL_IA32_ADDR 0x$SYSADDR" > ia32_addr.h
