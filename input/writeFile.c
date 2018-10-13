
#include <unistd.h>
#include <stdio.h>

int main(void)
{
	FILE* fp = fopen("\x0a", "w");
	fwrite("\x00\x00\x00\x00", 4 ,1, fp);
	return 0;
}
