/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <limits.h>
#include <string.h>
#include <time.h>

#include <fluent-bit/flb_output_throttle.h>

uint64_t flb_output_throttle_now_ms(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    return (uint64_t) GetTickCount64();
#else
    struct timespec now;
    uint64_t seconds;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) {
        return 0;
    }

    seconds = (uint64_t) now.tv_sec;
    if (seconds > UINT64_MAX / 1000) {
        return UINT64_MAX;
    }

    return seconds * 1000 + (uint64_t) now.tv_nsec / 1000000;
#endif
}

static uint64_t saturating_add(uint64_t left, uint64_t right)
{
    if (UINT64_MAX - left < right) {
        return UINT64_MAX;
    }

    return left + right;
}

static uint64_t local_ceiling(struct flb_output_throttle *throttle)
{
    uint32_t shifts;
    uint64_t value;

    value = throttle->base_ms;
    shifts = throttle->consecutive_rounds - 1;

    while (shifts > 0 && value < throttle->cap_ms) {
        if (value > throttle->cap_ms / 2) {
            value = throttle->cap_ms;
        }
        else {
            value *= 2;
        }
        shifts--;
    }

    return value;
}

static void expire_locked(struct flb_output_throttle *throttle, uint64_t now_ms)
{
    if (throttle->state == FLB_OUTPUT_THROTTLE_COOLDOWN &&
        now_ms >= throttle->until_ms) {
        throttle->state = FLB_OUTPUT_THROTTLE_READY;
    }
}

int flb_output_throttle_init(struct flb_output_throttle *throttle,
                             int enabled, uint64_t base_ms, uint64_t cap_ms)
{
    int result;

    if (throttle == NULL || base_ms == 0 || cap_ms < base_ms) {
        return -1;
    }

    memset(throttle, 0, sizeof(struct flb_output_throttle));
    throttle->enabled = enabled;
    throttle->state = FLB_OUTPUT_THROTTLE_READY;
    throttle->base_ms = base_ms;
    throttle->cap_ms = cap_ms;
    throttle->started_ms = 0;

    result = pthread_mutex_init(&throttle->lock, NULL);
    if (result != 0) {
        return -1;
    }

    return 0;
}

void flb_output_throttle_destroy(struct flb_output_throttle *throttle)
{
    pthread_mutex_destroy(&throttle->lock);
}

int flb_output_throttle_admit(struct flb_output_throttle *throttle,
                              uint64_t now_ms, uint64_t *generation)
{
    int result;

    if (throttle == NULL || generation == NULL) {
        return FLB_FALSE;
    }

    pthread_mutex_lock(&throttle->lock);

    if (throttle->state == FLB_OUTPUT_THROTTLE_STOPPING) {
        result = FLB_FALSE;
    }
    else if (throttle->enabled == FLB_FALSE) {
        *generation = 0;
        result = FLB_TRUE;
    }
    else {
        expire_locked(throttle, now_ms);
        if (throttle->state == FLB_OUTPUT_THROTTLE_COOLDOWN) {
            result = FLB_FALSE;
        }
        else {
            *generation = throttle->generation;
            result = FLB_TRUE;
        }
    }

    pthread_mutex_unlock(&throttle->lock);
    return result;
}

uint64_t flb_output_throttle_publish(struct flb_output_throttle *throttle,
                                     uint64_t now_ms, int hint_present,
                                     uint64_t hint_ms, uint64_t random_value)
{
    uint64_t floor;
    uint64_t span;
    uint64_t delay;
    uint64_t deadline;
    uint64_t ceiling;
    uint64_t old_deadline;

    pthread_mutex_lock(&throttle->lock);

    if (throttle->enabled == FLB_FALSE ||
        throttle->state == FLB_OUTPUT_THROTTLE_STOPPING) {
        deadline = throttle->until_ms;
        pthread_mutex_unlock(&throttle->lock);
        return deadline;
    }

    expire_locked(throttle, now_ms);
    old_deadline = 0;
    if (throttle->state == FLB_OUTPUT_THROTTLE_COOLDOWN) {
        old_deadline = throttle->until_ms;
    }
    else {
        throttle->started_ms = now_ms;
        if (throttle->consecutive_rounds < UINT32_MAX) {
            throttle->consecutive_rounds++;
        }
    }

    ceiling = local_ceiling(throttle);
    floor = ceiling / 2 + ceiling % 2;
    if (floor < throttle->base_ms) {
        floor = throttle->base_ms;
    }
    span = ceiling - floor;
    if (span == UINT64_MAX) {
        delay = random_value;
    }
    else {
        delay = floor + random_value % (span + 1);
    }
    if (hint_present == FLB_TRUE && hint_ms > delay) {
        delay = hint_ms;
    }

    deadline = saturating_add(now_ms, delay);
    if (deadline < old_deadline) {
        deadline = old_deadline;
    }

    throttle->until_ms = deadline;
    if (throttle->generation == UINT64_MAX) {
        throttle->state = FLB_OUTPUT_THROTTLE_STOPPING;
        pthread_mutex_unlock(&throttle->lock);
        return deadline;
    }
    throttle->generation++;
    throttle->events++;
    throttle->state = FLB_OUTPUT_THROTTLE_COOLDOWN;

    pthread_mutex_unlock(&throttle->lock);
    return deadline;
}

void flb_output_throttle_success(struct flb_output_throttle *throttle,
                                 uint64_t now_ms, uint64_t generation)
{
    pthread_mutex_lock(&throttle->lock);

    if (throttle->enabled == FLB_TRUE &&
        throttle->state != FLB_OUTPUT_THROTTLE_STOPPING) {
        expire_locked(throttle, now_ms);
        if (throttle->state == FLB_OUTPUT_THROTTLE_READY &&
            generation == throttle->generation) {
            throttle->consecutive_rounds = 0;
        }
    }

    pthread_mutex_unlock(&throttle->lock);
}

void flb_output_throttle_stop(struct flb_output_throttle *throttle)
{
    pthread_mutex_lock(&throttle->lock);
    throttle->state = FLB_OUTPUT_THROTTLE_STOPPING;
    pthread_mutex_unlock(&throttle->lock);
}

void flb_output_throttle_snapshot(struct flb_output_throttle *throttle,
                                  struct flb_output_throttle_snapshot *snapshot)
{
    pthread_mutex_lock(&throttle->lock);
    snapshot->enabled = throttle->enabled;
    snapshot->state = throttle->state;
    snapshot->started_ms = throttle->started_ms;
    snapshot->until_ms = throttle->until_ms;
    snapshot->generation = throttle->generation;
    snapshot->consecutive_rounds = throttle->consecutive_rounds;
    snapshot->events = throttle->events;
    pthread_mutex_unlock(&throttle->lock);
}
