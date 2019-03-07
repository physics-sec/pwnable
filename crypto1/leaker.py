from pwn import *
import requests
import re

context.log_level = 'error'
host = 'pwnable.kr'

# leak = you_will_never__________________
def getCT(name, pw, bloq):
	conn = remote(host ,9006)
	conn.recvline()
	conn.recvline()
	conn.recvline()
	conn.recvline()
	conn.recvline()
	conn.sendline(name)
	conn.recvline()
	conn.sendline(pw)
	line = conn.recvline()
	conn.close()
	ct = re.search(r'sending encrypted data \((.*?)\)', line).group(1)
	bloques = re.findall(r'(.{16})', ct)
	return bloques[bloq]

def leak():
	leak = ''
	chars = '_youwilnevrabcdfghjkmpqstxz1234567890-'
	for bloq in range(3):
		for i in range(14):
			name = 'a' * (13 - i)
			pw   = ''
			bloqueBuscado = getCT(name, pw, bloq)
			for char in chars:
				pw = '-' + leak + char
				bloqueObtenido = getCT(name, pw, bloq)
				if bloqueBuscado == bloqueObtenido:
					leak += char
					print leak
					break
			else:
				print 'Falied!'
				return
		for i in range(2):
			name = 'a' * (16 * (1 + bloq) - i)
			pw   = ''
			bloqueBuscado = getCT(name, pw, bloq + 1)
			for char in chars:
				pw = '-' + leak + char
				bloqueObtenido = getCT(name, pw, bloq + 1)
				if bloqueBuscado == bloqueObtenido:
					leak += char
					print leak
					break
			else:
				print 'Falied!'
				return

if __name__ == '__main__':
	try:
		leak()
	except KeyboardInterrupt:
		pass
