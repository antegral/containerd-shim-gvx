/*
 * Static C program for the acceptance tests of executables that link at a
 * fixed address. Build it with: gcc -O2 -static -no-pie -o cstatic cstatic.c
 *
 * The program keeps pointers in the data segment, reaches code through
 * function pointer tables, compares the addresses of objects, runs four
 * threads with a mutex and a condition variable, and jumps with longjmp. A
 * loader that moves the image must keep every one of these facts true.
 */
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node {
	const char *name;
	int value;
	struct node *next;
};

static struct node n3 = {"three", 3, 0};
static struct node n2 = {"two", 2, &n3};
static struct node n1 = {"one", 1, &n2};

static const char *words[] = {"pear", "apple", "fig", "kiwi"};

static int add_one(int x) { return x + 1; }
static int twice(int x) { return x * 2; }
static int (*const ops[])(int) = {add_one, twice};

static int compare_words(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t finished = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t *volatile lock_ptr = &lock;
static int done_count;
static int total;

static void *worker(void *arg)
{
	long id = (long)arg;
	for (int i = 0; i < 20000; i++) {
		pthread_mutex_lock(lock_ptr);
		total += (int)id;
		pthread_mutex_unlock(lock_ptr);
	}
	pthread_mutex_lock(lock_ptr);
	done_count++;
	pthread_cond_signal(&finished);
	pthread_mutex_unlock(lock_ptr);
	return 0;
}

static jmp_buf jump;

int main(void)
{
	for (struct node *p = &n1; p; p = p->next)
		printf("%s=%d\n", p->name, p->value);

	const char *sorted[4];
	memcpy(sorted, words, sizeof sorted);
	qsort(sorted, 4, sizeof *sorted, compare_words);
	for (int i = 0; i < 4; i++)
		printf("%s ", sorted[i]);
	printf("\n");

	for (int i = 0; i < 2; i++)
		printf("op%d=%d\n", i, ops[i](10));
	printf("identity next==&n2:%d lock_ptr==&lock:%d op0==add_one:%d\n",
	       n1.next == &n2, lock_ptr == &lock, ops[0] == add_one);

	pthread_t threads[4];
	for (long i = 0; i < 4; i++)
		pthread_create(&threads[i], 0, worker, (void *)i);
	pthread_mutex_lock(&lock);
	while (done_count < 4)
		pthread_cond_wait(&finished, &lock);
	pthread_mutex_unlock(&lock);
	for (int i = 0; i < 4; i++)
		pthread_join(threads[i], 0);
	printf("total %d\n", total);

	if (!setjmp(jump))
		longjmp(jump, 1);
	printf("longjmp ok\n");
	return 0;
}
