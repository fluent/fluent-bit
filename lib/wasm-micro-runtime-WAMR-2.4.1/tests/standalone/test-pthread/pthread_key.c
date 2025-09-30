/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

pthread_key_t key;
pthread_mutex_t lock;

struct test_struct {
    int i;
    int k;
};

typedef struct point {
    int x;
    int y;
} Point;

void *
child1(void *arg)
{
    struct test_struct struct_data;
    struct_data.i = 10;
    struct_data.k = 5;
    pthread_mutex_lock(&lock);
    pthread_setspecific(key, &struct_data);
    printf("thread1--address of struct_data is --> %p\n", &(struct_data));
    printf("thread1--from pthread_getspecific(key) get the pointer and it "
           "points to --> %p\n",
           (struct test_struct *)pthread_getspecific(key));
    printf("thread1--from pthread_getspecific(key) get the pointer and print "
           "it's content:\nstruct_data.i:%d\nstruct_data.k: %d\n",
           ((struct test_struct *)pthread_getspecific(key))->i,
           ((struct test_struct *)pthread_getspecific(key))->k);
    printf("------------------------------------------------------\n");
    pthread_mutex_unlock(&lock);
}

void *
child2(void *arg)
{
    int temp = 20;

    pthread_mutex_lock(&lock);
    printf("thread2--temp's address is %p\n", &temp);
    pthread_setspecific(key, &temp);
    printf("thread2--from pthread_getspecific(key) get the pointer and it "
           "points to --> %p\n",
           (int *)pthread_getspecific(key));
    printf("thread2--from pthread_getspecific(key) get the pointer and print "
           "it's content --> temp:%d\n",
           *((int *)pthread_getspecific(key)));
    printf("------------------------------------------------------\n");
    pthread_mutex_unlock(&lock);
}

int
main(void)
{
    Point p;
    p.x = 10;
    p.y = 20;
    pthread_t tid1, tid2;

    pthread_mutex_init(&lock, NULL);

    pthread_key_create(&key, NULL);
    pthread_create(&tid1, NULL, child1, NULL);
    pthread_create(&tid2, NULL, child2, NULL);

    pthread_mutex_lock(&lock);
    printf("main--temp's address is %p\n", &p);
    pthread_setspecific(key, &p);
    printf("main--from pthread_getspecific(key) get the pointer and it points "
           "to --> %p\n",
           (int *)pthread_getspecific(key));
    printf("main--from pthread_getspecific(key) get the pointer and print "
           "it's content --> x:%d, y:%d\n",
           ((Point *)pthread_getspecific(key))->x,
           ((Point *)pthread_getspecific(key))->y);
    pthread_mutex_unlock(&lock);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    pthread_key_delete(key);
    return 0;
}
