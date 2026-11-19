/* Portable coroutine runtime regression tests; license: public domain. */
#include "libco.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#ifdef _MSC_VER
#define TLS __declspec(thread)
#else
#define TLS __thread
#endif

/* Unlike assert(), checks remain enabled in Release builds. */
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); abort(); \
} } while (0)

static TLS cothread_t caller;
static TLS cothread_t first;
static TLS cothread_t second;
static TLS unsigned int hits;

static void second_entry(void)
{
    volatile unsigned long local = 0xabcdef;
    for (;;) {
        CHECK(co_active() == second);
        CHECK(local == 0xabcdef);
        hits++;
        co_switch(first);
    }
}

static void first_entry(void)
{
    volatile unsigned long stack[128];
    unsigned int i;
    unsigned int round = 0;
    double value = 1.25;
    for (i = 0; i < 128; i++) stack[i] = i * 31 + 7;
    for (;;) {
        CHECK(co_active() == first);
        co_switch(second);
        CHECK(co_active() == first);
        for (i = 0; i < 128; i++) CHECK(stack[i] == i * 31 + 7);
        CHECK(value == 1.25 + round * 0.5);
        value += 0.5;
        round++;
        co_switch(caller);
    }
}

static void create_pair(void)
{
    size_t allocated = 0;
    caller = co_active();
    CHECK(caller != NULL && co_active() == caller);
    first = co_create(256 * 1024, first_entry, &allocated);
    CHECK(first != NULL && allocated >= 256 * 1024);
    allocated = 0;
    second = co_create(256 * 1024, second_entry, &allocated);
    CHECK(second != NULL && allocated >= 256 * 1024);
    CHECK(first != second && first != caller && second != caller);
    hits = 0;
}

static void run_pair(unsigned int count)
{
    unsigned int start = hits;
    unsigned int i;
    for (i = 1; i <= count; i++) {
        co_switch(first);
        CHECK(co_active() == caller);
        CHECK(hits == start + i);
    }
}

static void delete_pair(void)
{
    co_delete(second);
    co_delete(first);
    CHECK(co_active() == caller);
}

#ifdef _WIN32
static DWORD WINAPI worker(void *unused)
#else
static void *worker(void *unused)
#endif
{
    unsigned int i;
    (void) unused;
    for (i = 0; i < 8; i++) {
        create_pair();
        run_pair(1000);
        delete_pair();
    }
    return 0;
}

int main(void)
{
    cothread_t main_caller;
#ifdef _WIN32
    HANDLE thread;
#else
    pthread_t thread;
#endif
    create_pair();
    main_caller = caller;
    run_pair(1000);
    /* Keep the main thread's coroutines suspended while a second OS thread
     * creates and runs its own. Serial creation also respects SJLJ's use of
     * a process-wide signal handler. */
#ifdef _WIN32
    thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    CHECK(thread != NULL);
    CHECK(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0);
    CHECK(CloseHandle(thread));
#else
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
#endif
    CHECK(co_active() == main_caller);
    run_pair(1000);
    delete_pair();
    puts("Coroutine switching, stack preservation, recreation and thread isolation passed");
    return 0;
}
