#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char *argv[] = {"pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn", "pwn"};
	argv['A'] = "\x00";
	argv['B'] = "\x20\x0a\x0d";
    argv['C'] = "1337";
	char *envp[] =
	{
		"\xde\xad\xbe\xef=\xca\xfe\xba\xbe",
		0
	};
	execve("./test", argv, envp);
	fprintf(stderr, "Oops!\n");
	return -1;
}
