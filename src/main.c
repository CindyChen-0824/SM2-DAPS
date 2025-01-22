#include "../inc/SM2.h"
#include "../inc/bench.h"
#include <stdio.h>
#include <stdlib.h>
int main()
{
	int tmp;
	tmp = SM2_SelfCheck();
	if (tmp != 0)
		printf("%d,Error!\n",tmp);
	else
	{
		printf("Success!\n");
	}

	bench_part();

	/*system("pause");*/

	return 0;
}