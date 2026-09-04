use std::collections::VecDeque;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Error)]
pub enum LandingZoneError {
    #[error("Attempted to remove non-observed element")]
    RemovingNonObservedElement,
}

/// Internal state for the landing zone.
///
/// Maintains two queues: one for unobserved items and one for observed items
/// that are waiting for acknowledgement.
struct LandingZoneState<T> {
    /// Queue of items that haven't been observed yet.
    queue: VecDeque<T>,
    /// Queue of items that have been observed but not yet removed.
    observed_items: VecDeque<T>,
}

/// A thread-safe queue with observation semantics and backpressure control.
///
/// The `LandingZone` provides a specialized queue where items must be "observed"
/// before they can be removed. This enables the sender and receiver tasks to
/// coordinate: the sender observes items from the queue and sends them over the
/// network, while the receiver removes observed items only after receiving
/// acknowledgements.
///
/// Key features:
/// - **Observe before remove**: Items must be observed before removal
/// - **Reset capability**: Observed items can be moved back to the queue for retry
/// - **Backpressure**: Enforces a maximum number of inflight requests via semaphore
/// - **Thread-safe**: Safe for concurrent access from multiple tasks
pub struct LandingZone<T: Clone> {
    /// Synchronizes access to the landing zone.
    state: Arc<std::sync::Mutex<LandingZoneState<T>>>,
    /// Notifies waiting `observe()` calls when new items are added.
    new_item_notify: Arc<Notify>,
    /// Controls maximum number of inflight requests to enforce backpressure.
    semaphore: Arc<Semaphore>,
    /// Tracks semaphore permits to release them when items are removed.
    permits: std::sync::Mutex<VecDeque<OwnedSemaphorePermit>>,
}

impl<T: Clone> LandingZone<T> {
    /// Creates a new `LandingZone` with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `max_inflight_requests` - Maximum number of requests that can be in the landing zone
    ///   (both observed and unobserved) at any time. When this limit is reached, `add()`
    ///   calls will block until items are removed.
    pub fn new(max_inflight_requests: usize) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(LandingZoneState {
                queue: VecDeque::with_capacity(max_inflight_requests),
                observed_items: VecDeque::with_capacity(max_inflight_requests),
            })),
            new_item_notify: Arc::new(Notify::new()),
            semaphore: Arc::new(Semaphore::new(max_inflight_requests)),
            permits: std::sync::Mutex::new(VecDeque::with_capacity(max_inflight_requests)),
        }
    }

    /// Removes all items from the landing zone, both observed and unobserved.
    ///
    /// This is typically used during stream failure to retrieve all pending records.
    ///
    /// # Returns
    ///
    /// A vector containing all items that were in the landing zone.
    pub fn remove_all(&self) -> Vec<T> {
        let mut state = self.state.lock().expect("Lock poisoned");

        let mut all_items = Vec::with_capacity(state.observed_items.len() + state.queue.len());
        all_items.extend(state.observed_items.drain(..));
        all_items.extend(state.queue.drain(..));

        let mut permits = self.permits.lock().expect("Lock poisoned");
        permits.clear();

        all_items
    }

    /// Adds an item to the queue.
    ///
    /// This method will block if the maximum number of inflight requests has been reached,
    /// providing automatic backpressure control.
    ///
    /// # Arguments
    ///
    /// * `request` - The item to add to the queue
    pub async fn add(&self, request: T) {
        let _permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Failed to acquire semaphore");
        let mut state = self.state.lock().expect("Lock poisoned");
        state.queue.push_back(request);
        self.permits
            .lock()
            .expect("Lock poisoned")
            .push_back(_permit);
        // Unblock one of the waiting observe() calls.
        self.new_item_notify.notify_one();
    }

    /// Removes and returns the next observed item.
    ///
    /// Items must be observed via `observe()` before they can be removed. This ensures
    /// proper coordination between sender and receiver tasks.
    ///
    /// # Returns
    ///
    /// * `Ok(T)` - The removed item
    /// * `Err(LandingZoneError::RemovingNonObservedElement)` - If no items have been observed
    pub fn remove_observed(&self) -> Result<T, LandingZoneError> {
        let mut state = self.state.lock().expect("Lock poisoned");
        if let Some(item) = state.observed_items.pop_front() {
            self.permits.lock().expect("Lock poisoned").pop_front();
            Ok(item)
        } else {
            Err(LandingZoneError::RemovingNonObservedElement)
        }
    }

    /// Observes the next item in the queue without removing it.
    ///
    /// This moves the item from the unobserved queue to the observed queue. The item
    /// remains in the landing zone until `remove_observed()` is called. This allows the
    /// sender to send items over the network while keeping them buffered for potential retry.
    ///
    /// This method will block if there are no items available to observe.
    ///
    /// # Returns
    ///
    /// The observed item (still retained in the landing zone).
    pub async fn observe(&self) -> T {
        loop {
            let notified = self.new_item_notify.notified();
            {
                let mut state = self.state.lock().expect("Lock poisoned");
                if let Some(elem) = state.queue.pop_front() {
                    state.observed_items.push_back(elem.clone());
                    return elem;
                }
            }
            notified.await;
        }
    }

    /// Resets observation by moving all observed items back to the queue.
    ///
    /// This is used during stream recovery to re-send items that were observed but
    /// not yet acknowledged by the server.
    pub fn reset_observe(&self) {
        let mut state = self.state.lock().expect("Lock poisoned");
        while let Some(observed_item) = state.observed_items.pop_back() {
            state.queue.push_front(observed_item);
        }
    }

    /// Checks if there are no observed items waiting for acknowledgement.
    ///
    /// # Returns
    ///
    /// `true` if the observed queue is empty, `false` otherwise.
    pub fn is_observed_empty(&self) -> bool {
        let state = self.state.lock().expect("Lock poisoned");
        state.observed_items.is_empty()
    }

    /// Returns the number of in-flight requests in the landing zone.
    pub fn len(&self) -> usize {
        let state = self.state.lock().expect("Lock poisoned");
        state.queue.len() + state.observed_items.len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::time::{timeout, Duration};

    use super::{LandingZone, LandingZoneError};

    #[tokio::test]
    async fn test_add_and_observe() {
        let lz = Arc::new(LandingZone::new(10));

        lz.add("test_item".to_string()).await;

        let observed = lz.observe().await;
        assert_eq!(observed, "test_item");
    }

    #[tokio::test]
    async fn test_observe_blocks_until_item_available() {
        let lz = Arc::new(LandingZone::new(10));
        let lz_clone = lz.clone();

        // Start observing in background.
        let observe_task = tokio::spawn(async move { lz_clone.observe().await });

        // Give it time to start waiting.
        tokio::time::sleep(Duration::from_millis(10)).await;

        lz.add("delayed_item".to_string()).await;

        // Should unblock and return the item.
        let result = timeout(Duration::from_millis(100), observe_task).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), "delayed_item");
    }

    #[tokio::test]
    async fn test_remove_observed() {
        let lz = Arc::new(LandingZone::new(10));

        lz.add("item1".to_string()).await;
        let _observed = lz.observe().await;

        let removed = lz.remove_observed().unwrap();
        assert_eq!(removed, "item1");
    }

    #[tokio::test]
    async fn test_remove_non_observed_fails() {
        let lz = Arc::new(LandingZone::<String>::new(10));

        let result = lz.remove_observed();
        assert!(matches!(
            result,
            Err(LandingZoneError::RemovingNonObservedElement)
        ));
    }

    #[tokio::test]
    async fn test_remove_all() {
        let lz = Arc::new(LandingZone::new(10));

        lz.add("item1".to_string()).await;
        lz.add("item2".to_string()).await;

        let _observed = lz.observe().await;

        let all_items = lz.remove_all();
        assert_eq!(all_items.len(), 2);
        assert!(all_items.contains(&"item1".to_string()));
        assert!(all_items.contains(&"item2".to_string()));

        assert!(lz.len() == 0);
    }

    #[tokio::test]
    async fn test_semaphore_limits_capacity() {
        let lz = Arc::new(LandingZone::new(2));

        lz.add("item1".to_string()).await;
        lz.add("item2".to_string()).await;

        // Third add should block (test with timeout).
        let mut add_task = tokio::spawn({
            let lz = lz.clone();
            async move {
                lz.add("item3".to_string()).await;
            }
        });
        // Should timeout because semaphore is full.
        tokio::select! {
            _ = &mut add_task => {
                panic!("add_task should not complete while semaphore is full");
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                // This is expected, the task is still blocked.
            }
        };

        // Remove one item to free up space.
        let _observed = lz.observe().await;
        let _removed = lz.remove_observed().unwrap();

        // Now the add_task should complete.
        add_task.await.unwrap();

        let all_items = lz.remove_all();
        assert_eq!(all_items.len(), 2);
        assert!(all_items.contains(&"item2".to_string()));
        assert!(all_items.contains(&"item3".to_string()));
    }

    #[tokio::test]
    async fn test_reset_observe_with_concurrent_add() {
        let lz = Arc::new(LandingZone::new(10));

        lz.add("item1".to_string()).await;
        lz.add("item2".to_string()).await;
        lz.add("item3".to_string()).await;

        let observed = lz.observe().await;
        assert_eq!(observed, "item1");

        // In another thread, add 4th item.
        let lz_clone = lz.clone();
        let add_task = tokio::spawn(async move {
            lz_clone.add("item4".to_string()).await;
        });

        add_task.await.unwrap();

        lz.reset_observe();

        assert_eq!(lz.observe().await, "item1");
        assert_eq!(lz.observe().await, "item2");
        assert_eq!(lz.observe().await, "item3");
        assert_eq!(lz.observe().await, "item4");
    }

    #[tokio::test]
    async fn test_semaphore_with_observe_reset() {
        let lz = Arc::new(LandingZone::new(2));

        lz.add("item1".to_string()).await;
        lz.add("item2".to_string()).await;

        // Observe one (should not free semaphore permit yet).
        let _observed = lz.observe().await;

        // Adding should still block because permit not released until remove_observed.
        let add_task = tokio::spawn({
            let lz = lz.clone();
            async move {
                lz.add("item3".to_string()).await;
            }
        });

        let result = timeout(Duration::from_millis(50), add_task).await;
        assert!(result.is_err()); // Should timeout.

        // Reset observe (item goes back to queue, still no permit freed).
        lz.reset_observe();

        // Remove observed should fail (nothing observed now).
        assert!(lz.remove_observed().is_err());

        // Only after actually removing an observed item should permit be freed and add_task should complete.
        let _observed_again = lz.observe().await;
        let _removed = lz.remove_observed().unwrap();

        // Remove item_3.
        let _observed_again_2 = lz.observe().await;
        let _removed_2 = lz.remove_observed().unwrap();

        // Now add should work.
        lz.add("item4".to_string()).await;
    }

    #[tokio::test]
    async fn test_is_observed_empty() {
        let lz = Arc::new(LandingZone::new(16));

        // Initially, observed queue should be empty
        assert!(lz.is_observed_empty());

        lz.add("item1".to_string()).await;
        // Still empty because we haven't observed yet
        assert!(lz.is_observed_empty());

        lz.observe().await;
        // Now it should not be empty
        assert!(!lz.is_observed_empty());

        lz.remove_observed().unwrap();
        // After removal, should be empty again
        assert!(lz.is_observed_empty());
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let lz = Arc::new(LandingZone::new(100));

        // Spawn multiple tasks that add items
        let mut add_tasks = vec![];
        for i in 0..10 {
            let lz_clone = lz.clone();
            add_tasks.push(tokio::spawn(async move {
                lz_clone.add(format!("item{}", i)).await;
            }));
        }

        // Spawn multiple tasks that observe items
        let mut observe_tasks = vec![];
        for _ in 0..10 {
            let lz_clone = lz.clone();
            observe_tasks.push(tokio::spawn(async move {
                lz_clone.observe().await;
            }));
        }

        // Wait for all add tasks to complete
        for task in add_tasks {
            task.await.unwrap();
        }

        // Wait for all observe tasks to complete
        let mut observed_items = vec![];
        for task in observe_tasks {
            observed_items.push(task.await);
        }

        // All 10 items should have been observed
        assert_eq!(observed_items.len(), 10);
    }
}
