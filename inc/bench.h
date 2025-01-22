#ifndef BENCH_H
#define BENCH_H
#include<stdlib.h>
#include<time.h>
#include<Windows.h>
#include<string.h>
#include<stdint.h>

#define CLOCK(TEST_TIMES,LABEL, FUNCTION)                           \
  do																\
  {                                                                 \
		int i;														\
		uint64_t start_time, end_time;								\
		for (i = 0; i < 1000; i++) FUNCTION;						\
		start_time = GetTickCount64();								\
		for (i = 0; i < TEST_TIMES; i++)							\
		{															\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
			FUNCTION;												\
		}															\
		end_time = GetTickCount64();								\
		printf("Timing %s\n",LABEL);								\
		printf("  - Total time : %lld ms\n", end_time-start_time);	\
		printf("  - Throughput: %8.1f op/sec\n", 1e3 * 10 * TEST_TIMES / (double)(end_time-start_time));\
		printf("  - Latency: %8.1f ns/op\n", (double)((end_time-start_time)*1000000/(10*TEST_TIMES)));\
  } while (0)

#define bench_function(TEST_TIMES,LABEL, FUNCTION) CLOCK(TEST_TIMES, LABEL, FUNCTION)

void bench_part();

#endif