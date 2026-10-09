//! Process-wide client-side warnings that surface common SDK misuse patterns.
//!
//! A warning is emitted via [`tracing::warn!`] when 100 or more streams for
//! the same table are opened within a 60-second sliding window, which usually
//! indicates a "one stream per record" misuse pattern.
//!
//! The warning is process-wide and keyed by table name.
//!
//! ## Opt-out
//!
//! Set the environment variable `ZEROBUS_SDK_WARNINGS_ENABLED=false` (or `0`
//! or `no`) before the process starts to suppress all warnings.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use tracing::warn;

// ─── Opt-out ──────────────────────────────────────────────────────────────────

fn warnings_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("ZEROBUS_SDK_WARNINGS_ENABLED")
            .map(|v| !matches!(v.to_lowercase().as_str(), "false" | "0" | "no"))
            .unwrap_or(true)
    })
}

// ─── Stream churn monitor ─────────────────────────────────────────────────────

/// Sliding window length in milliseconds.
const CHURN_WINDOW_MS: u64 = 60_000;
/// Logs a warning when this many streams are opened within [`CHURN_WINDOW_MS`].
const CHURN_WARN_THRESHOLD: usize = 100;
/// Maximum number of distinct tables tracked; oldest is evicted when exceeded.
const CHURN_MAX_TABLES: usize = 1000;

fn default_clock_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct StreamChurnState {
    /// Replaceable clock; overridden in tests to control time.
    clock: fn() -> u64,
    /// Per-table queue of stream-open timestamps (ms since Unix epoch).
    timestamps: HashMap<String, VecDeque<u64>>,
    /// Tracks insertion order for eviction when `CHURN_MAX_TABLES` is reached.
    insertion_order: VecDeque<String>,
}

impl StreamChurnState {
    fn new() -> Self {
        Self {
            clock: default_clock_ms,
            timestamps: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }
}

static CHURN_MONITOR: OnceLock<Mutex<StreamChurnState>> = OnceLock::new();

fn churn_monitor() -> &'static Mutex<StreamChurnState> {
    CHURN_MONITOR.get_or_init(|| Mutex::new(StreamChurnState::new()))
}

/// Records one user-initiated stream creation for `table_name`.
///
/// Maintains a per-table sliding window of creation timestamps. Logs a
/// `WARN`-level message when the count within the window reaches
/// [`CHURN_WARN_THRESHOLD`] (100), and again each time the window drains
/// and a new surge reaches the threshold.
///
/// Must only be called from user-facing stream creation paths, not from internal
/// reconnect / recovery paths.
pub(crate) fn record_stream_creation(table_name: &str) {
    if !warnings_enabled() {
        return;
    }

    let count = {
        let mut state = churn_monitor().lock().unwrap_or_else(|e| e.into_inner());
        let now = (state.clock)();

        if !state.timestamps.contains_key(table_name) {
            // Evict the oldest-tracked table when the cap is reached.
            if state.insertion_order.len() >= CHURN_MAX_TABLES {
                if let Some(oldest) = state.insertion_order.pop_front() {
                    state.timestamps.remove(&oldest);
                }
            }
            state
                .timestamps
                .insert(table_name.to_string(), VecDeque::new());
            state.insertion_order.push_back(table_name.to_string());
        }

        let deque = state.timestamps.get_mut(table_name).unwrap();
        // Evict timestamps that have fallen outside the sliding window.
        while deque
            .front()
            .map(|&t| now.saturating_sub(t) > CHURN_WINDOW_MS)
            .unwrap_or(false)
        {
            deque.pop_front();
        }
        deque.push_back(now);
        deque.len()
    };

    // Fire exactly when the window count hits the threshold; re-fires each time
    // the window drains below the threshold and a new surge reaches it.
    if count == CHURN_WARN_THRESHOLD {
        warn!(
            "Zerobus SDK: {} ingest streams opened for table `{}` in the last {}s in this \
             process. If this is unexpected, check that streams are being reused across records.",
            count,
            table_name,
            CHURN_WINDOW_MS / 1000
        );
    }
}

// ─── Test utilities ───────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) fn reset_for_testing() {
    if let Ok(mut state) = churn_monitor().lock() {
        *state = StreamChurnState::new();
    }
}

#[cfg(test)]
pub(crate) fn set_churn_clock_for_testing(f: fn() -> u64) {
    if let Ok(mut state) = churn_monitor().lock() {
        state.clock = f;
    }
}

#[cfg(test)]
pub(crate) fn open_count_in_window_for_testing(table_name: &str) -> usize {
    let state = churn_monitor().lock().unwrap_or_else(|e| e.into_inner());
    let now = (state.clock)();
    state
        .timestamps
        .get(table_name)
        .map(|deque| {
            deque
                .iter()
                .filter(|&&t| now.saturating_sub(t) <= CHURN_WINDOW_MS)
                .count()
        })
        .unwrap_or(0)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    use super::*;

    // All tests share a global fake clock and call reset_for_testing(). Each
    // acquires the serial lock so they run one at a time without corrupting
    // each other's clock or timestamp state.
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    static FAKE_CLOCK_MS: AtomicU64 = AtomicU64::new(0);

    fn fake_clock() -> u64 {
        FAKE_CLOCK_MS.load(Ordering::Relaxed)
    }

    #[test]
    fn churn_open_count_tracks_opens_within_window() {
        let _lock = serial();
        reset_for_testing();
        set_churn_clock_for_testing(fake_clock);
        FAKE_CLOCK_MS.store(0, Ordering::Relaxed);
        let table = "cat.sch.churn_tracks";

        record_stream_creation(table);
        record_stream_creation(table);
        assert_eq!(open_count_in_window_for_testing(table), 2);
    }

    #[test]
    fn churn_entries_older_than_window_evicted_on_next_open() {
        let _lock = serial();
        reset_for_testing();
        set_churn_clock_for_testing(fake_clock);
        FAKE_CLOCK_MS.store(0, Ordering::Relaxed);
        let table = "cat.sch.churn_evict";

        for _ in 0..10 {
            record_stream_creation(table);
        }
        assert_eq!(open_count_in_window_for_testing(table), 10);

        // Advance past the window; the next open evicts all 10 old entries.
        FAKE_CLOCK_MS.store(61_000, Ordering::Relaxed);
        record_stream_creation(table);
        assert_eq!(open_count_in_window_for_testing(table), 1);
    }

    #[test]
    fn churn_warning_fires_at_exactly_threshold_not_before() {
        let _lock = serial();
        reset_for_testing();
        set_churn_clock_for_testing(fake_clock);
        FAKE_CLOCK_MS.store(0, Ordering::Relaxed);
        let table = "cat.sch.churn_threshold";

        for _ in 0..99 {
            record_stream_creation(table);
        }
        assert_eq!(open_count_in_window_for_testing(table), 99);

        // 100th open crosses the threshold.
        record_stream_creation(table);
        assert_eq!(open_count_in_window_for_testing(table), 100);

        // 101st does not re-fire (count != CHURN_WARN_THRESHOLD).
        record_stream_creation(table);
        assert_eq!(open_count_in_window_for_testing(table), 101);
    }

    #[test]
    fn churn_warning_refires_after_window_rolls_below_threshold() {
        let _lock = serial();
        reset_for_testing();
        set_churn_clock_for_testing(fake_clock);
        FAKE_CLOCK_MS.store(0, Ordering::Relaxed);
        let table = "cat.sch.churn_refire";

        for _ in 0..100 {
            record_stream_creation(table);
        }
        assert_eq!(open_count_in_window_for_testing(table), 100);

        // Advance past window so all previous opens are evicted.
        FAKE_CLOCK_MS.store(61_000, Ordering::Relaxed);
        for _ in 0..99 {
            record_stream_creation(table);
        }
        assert_eq!(open_count_in_window_for_testing(table), 99);

        // 100th open in the new window crosses the threshold again.
        record_stream_creation(table);
        assert_eq!(open_count_in_window_for_testing(table), 100);
    }

    #[test]
    fn churn_two_tables_tracked_independently() {
        let _lock = serial();
        reset_for_testing();
        set_churn_clock_for_testing(fake_clock);
        FAKE_CLOCK_MS.store(0, Ordering::Relaxed);
        let t1 = "cat.sch.churn_indep1";
        let t2 = "cat.sch.churn_indep2";

        for _ in 0..5 {
            record_stream_creation(t1);
        }
        for _ in 0..3 {
            record_stream_creation(t2);
        }
        assert_eq!(open_count_in_window_for_testing(t1), 5);
        assert_eq!(open_count_in_window_for_testing(t2), 3);
    }

    #[test]
    fn churn_unknown_table_returns_zero() {
        assert_eq!(
            open_count_in_window_for_testing("cat.sch.churn_unknown_xyz"),
            0
        );
    }
}
