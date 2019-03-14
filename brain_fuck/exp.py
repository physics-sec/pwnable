#! /usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#r2 -e dbg.profile=bf.rr2

remoto = False
remoto = True
if remoto:
	host = 'pwnable.kr'
	host = '0'
	conn = connect(host, 9001)
else:
	conn = process('./bf')

def main():
	payload = '+'
	conn.recvuntil('[ ]\n')
	assert payload <= 1024
	conn.sendline(payload)

	conn.close()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass