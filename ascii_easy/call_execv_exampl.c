#include <stdio.h>
int main()
{
	setresuid(geteuid(), geteuid(), geteuid());
	execlp("/bin/sh", NULL);
}