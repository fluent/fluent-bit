#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

char* c_filter(char* tag, int len, uint32_t sec, uint32_t nsec, char* record, int record_len)
{
    char *buf;
    buf = malloc(1024);
    if (!buf) {
        printf("malloc buf failed\n");
        return NULL;
    }

    struct timespec ts;
    ts.tv_sec = sec;
    ts.tv_nsec = nsec;

    sprintf(buf, "{\"tag\":\"%s\",\"time\":\"%lld.%9ld\", \"message\":\"Hello, from C!\", \"original\": %s}",
            tag, (long long)ts.tv_sec, ts.tv_nsec, record);
    return buf;
}
