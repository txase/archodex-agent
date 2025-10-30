use crate::engine::resource_capture::ResourceIdPart;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex as TokioMutex;
use tracing::{instrument, warn};

/// Tracks unique resources across agent lifetime with deduplication.
#[derive(Debug)]
pub struct ResourceTracker {
    unique_resources: Arc<TokioMutex<HashSet<ResourceIdPart>>>,
    count: Arc<AtomicUsize>,
    limit_hit: Arc<AtomicBool>,
    max_resources: usize,
}

impl ResourceTracker {
    /// Create new resource tracker with specified limit
    pub fn new(max_resources: usize) -> Self {
        Self {
            unique_resources: Arc::new(TokioMutex::new(HashSet::new())),
            count: Arc::new(AtomicUsize::new(0)),
            limit_hit: Arc::new(AtomicBool::new(false)),
            max_resources,
        }
    }

    /// Check if limit flag is set
    fn is_limit_hit(&self) -> bool {
        self.limit_hit.load(Ordering::Acquire)
    }

    /// Set limit flag
    fn set_limit_hit(&self) {
        self.limit_hit.store(true, Ordering::Release);
    }

    /// Track resources from a report, returning (`new_count`, `hit_limit_now`).
    ///
    /// Extracts `ResourceIdPart` from report, deduplicates via `HashSet`,
    /// and updates count atomically. Returns the new total count and
    /// whether the limit was newly hit by this call.
    #[instrument(skip(self, resource_ids), fields(count = resource_ids.len()))]
    pub async fn track_resources(&mut self, resource_ids: Vec<ResourceIdPart>) -> (usize, bool) {
        let mut resources = self.unique_resources.lock().await;

        // Add all new resources to the set
        for id in resource_ids {
            resources.insert(id);
        }

        let new_count = resources.len();

        // Update atomic counter for fast reads
        self.count.store(new_count, Ordering::Relaxed);

        // Check if we just hit the limit
        let was_limited = self.is_limit_hit();
        let hit_limit_now = !was_limited && new_count > self.max_resources;

        if hit_limit_now {
            self.set_limit_hit();
            warn!(
                resource_count = new_count,
                limit = self.max_resources,
                "Resource limit exceeded, logging will stop after this report"
            );
        }

        (new_count, hit_limit_now)
    }

    /// Get current resource count
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Check if resource limit already exceeded
    pub fn is_limited(&self) -> bool {
        self.is_limit_hit()
    }
}
