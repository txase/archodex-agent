use crate::engine::report::Report;
use chrono::{DateTime, Days, Duration, Timelike, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Tracks events within a clock hour boundary (0-23 UTC).
///
/// Count resets to 0 when a new hour is detected.
#[derive(Debug)]
pub(crate) struct HourWindow {
    pub(crate) current_hour: u32,
    pub(crate) count: Arc<AtomicUsize>,
    pub(crate) started_at: DateTime<Utc>,
}

impl HourWindow {
    pub(crate) fn new(hour: u32, started_at: DateTime<Utc>) -> Self {
        Self {
            current_hour: hour,
            count: Arc::new(AtomicUsize::new(0)),
            started_at,
        }
    }

    /// Returns true if timestamp is in a different clock hour than current window.
    pub(crate) fn has_hour_changed(&self, timestamp: DateTime<Utc>) -> bool {
        EventTracker::current_window(timestamp) != self.current_hour
    }

    /// Resets counter and transitions to new hour.
    pub(crate) fn reset_for_hour(&mut self, new_hour: u32, timestamp: DateTime<Utc>) {
        debug!(
            old_hour = self.current_hour,
            old_count = self.count.load(Ordering::Relaxed),
            new_hour = new_hour,
            "Resetting event counter for new clock hour"
        );

        self.current_hour = new_hour;
        self.count.store(0, Ordering::Relaxed);
        self.started_at = timestamp;
    }
}

/// Event tracker with automatic hour boundary detection
#[derive(Debug)]
pub(crate) struct EventTracker {
    window: Arc<Mutex<HourWindow>>,
    limit: usize,
    limit_hit: Arc<AtomicBool>,
}

impl EventTracker {
    const WINDOW_DURATION_MINUTES: u32 = 60;

    /// Calculate current time window from timestamp.
    fn current_window(timestamp: DateTime<Utc>) -> u32 {
        let total_minutes = (timestamp.hour() * 60) + timestamp.minute();
        total_minutes / Self::WINDOW_DURATION_MINUTES
    }

    /// Create new event tracker with specified limit.
    ///
    /// Initializes with current clock hour from system time.
    pub(crate) fn new(max_events: usize) -> Self {
        let now = Utc::now();
        Self {
            window: Arc::new(Mutex::new(HourWindow::new(Self::current_window(now), now))),
            limit: max_events,
            limit_hit: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if limit flag is set (Acquire ordering for synchronization).
    fn is_limit_hit(&self) -> bool {
        self.limit_hit.load(Ordering::Acquire)
    }

    /// Set limit flag (Release ordering to publish all previous writes).
    fn set_limit_hit(&self) {
        self.limit_hit.store(true, Ordering::Release);
    }

    /// Clear limit flag (Release ordering to publish hour reset).
    fn clear_limit_hit(&self) {
        self.limit_hit.store(false, Ordering::Release);
    }

    /// Check for hour boundary and reset counter if needed.
    ///
    /// Returns true if hour changed and counter was reset.
    pub(crate) async fn check_hour_boundary(&mut self, now: DateTime<Utc>) -> bool {
        let mut window = self.window.lock().await;

        if window.has_hour_changed(now) {
            let new_hour = Self::current_window(now);
            info!(
                old_hour = window.current_hour,
                new_hour = new_hour,
                "Hour boundary detected, resetting event counter"
            );

            window.reset_for_hour(new_hour, now);
            self.clear_limit_hit();
            true
        } else {
            false
        }
    }

    /// Track events from report, returning (`new_count`, `hit_limit_now`).
    pub(crate) async fn track_events(&mut self, report: &Report) -> (usize, bool) {
        let event_count = report.count_events();
        let window = self.window.lock().await;

        let previous_count = window.count.load(Ordering::Relaxed);
        let new_count = previous_count + event_count;
        window.count.store(new_count, Ordering::Relaxed);

        // Check if we just exceeded the limit
        let already_limited = self.is_limit_hit();
        let hit_limit_now = !already_limited && new_count > self.limit;

        if hit_limit_now {
            self.set_limit_hit();
            warn!(
                event_count = new_count,
                limit = self.limit,
                "Event limit exceeded for current hour"
            );
        }

        (new_count, hit_limit_now)
    }

    /// Get current event count
    pub(crate) async fn count(&self) -> usize {
        let window = self.window.lock().await;
        window.count.load(Ordering::Relaxed)
    }

    /// Check if event limit has been exceeded
    pub(crate) fn is_limited(&self) -> bool {
        self.is_limit_hit()
    }

    /// Calculate time remaining until next clock hour boundary.
    pub(crate) async fn time_until_reset(&self) -> Duration {
        let window = self.window.lock().await;
        let now = Utc::now();

        // Calculate next hour boundary
        let next_hour = (window.current_hour + 1) % 24;
        let next_boundary = if next_hour > window.current_hour {
            now.date_naive()
                .and_hms_opt(next_hour, 0, 0)
                .unwrap()
                .and_utc()
        } else {
            // Next day
            (now.date_naive() + Days::new(1))
                .and_hms_opt(next_hour, 0, 0)
                .unwrap()
                .and_utc()
        };

        next_boundary - now
    }
}
