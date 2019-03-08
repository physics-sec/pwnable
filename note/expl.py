from pwn import *

host = '0'
host = 'pwnable.kr'

"""
- Select Menu -
1. create note
2. write note
3. read note
4. delete note
5. exit
"""

def main():
	conn = remote(host, 9019)
	conn.readuntil('5. exit\n')


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass
