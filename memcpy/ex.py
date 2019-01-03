#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import telnetlib
import struct
import random

p64 = lambda data: struct.pack("Q", data)
u64 = lambda data: struct.unpack("Q", data)
p32 = lambda data: struct.pack("I", data)
u32 = lambda data: struct.unpack("I", data)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
s.connect(('127.0.0.1', 9022))

"""
def read_all():
	global s
	b = b""
	last_recv = True
	while last_recv:
		try:
			last_recv = s.recv(1024)
		except socket.timeout:
			last_recv = None
		if last_recv:
			b += last_recv
	return b.decode('utf-8')
"""

def recv(n):
	global s
	b = b""
	while len(b) < n:
		try:
			b += s.recv(n - len(b))
		except socket.timeout:
			break
	return b.decode('utf-8')

def send(msg):
	global s
	s.send(msg.encode() + b'\n')

def main():
	a = recv(1024)
	print(a)
	num = str(11)
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(22)
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(40)
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(96)
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(random.randint(128, 256))
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(random.randint(256, 512))
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(random.randint(512, 1024))
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(random.randint(1024, 2048))
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(random.randint(2048, 4096))
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	num = str(random.randint(4096, 8192))
	send(num)
	print(num)
	a = recv(1024)
	print(a)
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()


if __name__ == '__main__':
	main()
