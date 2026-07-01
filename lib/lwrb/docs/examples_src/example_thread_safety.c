/* Declare variables */
lwrb_t rb;

/* 2 mutexes, one for write operations,
    one for read operations */
mutex_t m_w, m_r;

/* 4 threads below, 2 for write, 2 for read */
void
thread_write_1(void* arg) {
    /* Use write mutex */
    while (1) {
        mutex_get(&m_w);
        lwrb_write(&rb, ...);
        mutex_give(&m_w);
    }
}

void
thread_write_2(void* arg) {
    /* Use write mutex */
    while (1) {
        mutex_get(&m_w);
        lwrb_write(&rb, ...);
        mutex_give(&m_w);
    }
}

void
thread_read_1(void* arg) {
    /* Use read mutex */
    while (1) {
        mutex_get(&m_r);
        lwrb_read(&rb, ...);
        mutex_give(&m_r);
    }
}

void
thread_read_2(void* arg) {
    /* Use read mutex */
    while (1) {
        mutex_get(&m_r);
        lwrb_read(&rb, ...);
        mutex_give(&m_r);
    }
}