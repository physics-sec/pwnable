mov rax, 0x0047464544434241
push rax
mov r10, rsp # direc del nombre

sub rsp, 0x100
mov r9, rsp # direc del buffer

mov rsi, 0
mov rdi, r10
mov rax, 2
syscall
mov rbx, rax

mov rdx, 0x100
mov rsi, rsp
mov rdi, rbx
mov rax, 0
syscall

mov rdx, 0x100
mov rsi, rsp
mov rdi, 1
mov rax, 1
syscall