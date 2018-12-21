#include <stdio.h>

#define FILENAME "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

int main(int argc, char* argv[])
{
	FILE *fp;
	//fp = fopen(FILENAME, "rb");
	//if (fp)
	//{
	//	printf("opened!\n");
	//}
	//else
	//{
	//	printf("NOT opened\n");
	//}

	fp = fopen(FILENAME, "wb");
	if (!fp)
	{
		printf("no se pudo crear");
	}
	else
	{
		printf("se pudo crear");
	}
	return 0;
}
