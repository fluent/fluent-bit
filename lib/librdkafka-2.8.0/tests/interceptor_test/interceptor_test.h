#ifndef _INTERCEPTOR_TEST_H_
#define _INTERCEPTOR_TEST_H_


struct ictcnt {
        int cnt;
        int min;
        int max;
};

struct ictest {
        struct ictcnt conf_init;
        struct ictcnt on_new;

        /* intercepted interceptor_test.config1 and .config2 properties */
        char *config1;
        char *config2;

        /* intercepted session.timeout.ms and socket.timeout.ms */
        char *session_timeout_ms;
        char *socket_timeout_ms;
};

#define ictest_init(ICT) memset((ICT), 0, sizeof(ictest))
#define ictest_cnt_init(CNT, MIN, MAX)                                         \
        do {                                                                   \
                (CNT)->cnt = 0;                                                \
                (CNT)->min = MIN;                                              \
                (CNT)->max = MAX;                                              \
        } while (0)

#define ictest_free(ICT)                                                       \
        do {                                                                   \
                if ((ICT)->config1)                                            \
                        free((ICT)->config1);                                  \
                if ((ICT)->config2)                                            \
                        free((ICT)->config2);                                  \
                if ((ICT)->session_timeout_ms)                                 \
                        free((ICT)->session_timeout_ms);                       \
                if ((ICT)->socket_timeout_ms)                                  \
                        free((ICT)->socket_timeout_ms);                        \
        } while (0)

#define ICTEST_CNT_CHECK(F)                                                    \
        do {                                                                   \
                if (ictest.F.cnt > ictest.F.max)                               \
                        TEST_FAIL("interceptor %s count %d > max %d", #F,      \
                                  ictest.F.cnt, ictest.F.max);                 \
        } while (0)

/* The ictest struct is defined and set up by the calling test. */
extern struct ictest ictest;

#endif /* _INTERCEPTOR_TEST_H_ */
