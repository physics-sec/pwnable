from pwn import *
import requests
import hashlib
import re
import sys

# byte to byte leaking against block cipher plaintext is fun!!

context.log_level = 'error'
host = 'pwnable.kr'
host = '0'

def getLenCookie():
	name = ''
	ct = getCT('','')
	min_len_ct = len(ct) / 2
	while True:
		ct = getCT(name,'')
		len_ct = len(ct) / 2
		if len_ct > min_len_ct:
			payloadSize = len_ct - 16
			cookieSize = payloadSize - len(name) - 2
			print 'la cookie tiene {:d} caracteres'.format(cookieSize)
			return cookieSize
		name += 'a'

def getCT(name, pw, bloq=None):
	conn = remote(host ,9006)
	conn.recvuntil('Input your ID\n')
	conn.sendline(name)
	conn.recvuntil('Input your PW\n')
	conn.sendline(pw)
	line = conn.recvline()
	conn.close()
	ct = re.search(r'sending encrypted data \((.*?)\)', line).group(1)
	if bloq is not None:
		bloques = re.findall(r'(.{32})', ct) # 16 bytes -> 32 caracteres
		return bloques[bloq]
	return ct

def get_pw(cookie):
	return hashlib.sha256('admin' + cookie).hexdigest()

def merca():
	leak = 'you_will_never_guess_this_suga'
	bloq = len(leak) + 2
	bloq = bloq // 16

def leak():
	leak = ''
	chars = '_youwilnevrgsthabcdfjkmpqxz1234567890-'
	for bloq in range(4):
		print 'bloq:' + str(bloq)
		print 'primer loop'
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
					if len(leak) == 49:
						print 'Cookie: ' + leak
						print '    ID: admin'
						print '    PW: ' + get_pw(leak)
						return
					break
			else:
				print 'Failed!'
				return
		print 'segundo loop'
		for i in range(2):
			name = 'a' * (16 - 1 - i)
			pw   = ''
			bloqueBuscado = getCT(name, pw, bloq + 1)
			for char in chars:
				pw = '-' + leak + char
				bloqueObtenido = getCT(name, pw, bloq + 1)
				if bloqueBuscado == bloqueObtenido:
					leak += char
					print leak
					if len(leak) == 49:
						print 'Cookie:' + leak
						print '    ID:admin'
						print '    PW:' + get_pw(leak)
						return
					break
			else:
				print 'Failed!'
				return

if __name__ == '__main__':
	try:
		leak()
	except KeyboardInterrupt:
		pass
