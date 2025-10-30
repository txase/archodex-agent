use crate::engine::report::Report;
use crate::license_enforcement::event_tracker::EventTracker;
use crate::license_enforcement::resource_tracker::ResourceTracker;
use chrono::{Duration, Timelike};
use tracing::debug;
use tracing::instrument;

/// Operating mode that determines license enforcement thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatingMode {
    Standalone,
    Team,
}

impl std::fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatingMode::Standalone => write!(f, "Standalone"),
            OperatingMode::Team => write!(f, "Team"),
        }
    }
}

/// License enforcement configuration for a specific operating mode.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ModeLimits {
    pub(crate) max_resources: usize,
    pub(crate) max_events: usize,
}

impl ModeLimits {
    /// Get limit configuration for the specified operating mode.
    pub(crate) fn for_mode(mode: OperatingMode) -> Self {
        match mode {
            OperatingMode::Standalone => Self {
                max_resources: 50,
                max_events: 100,
            },
            OperatingMode::Team => Self {
                max_resources: 500,
                max_events: 1000,
            },
        }
    }
}

/// Tracks which license enforcement limits are currently active.
#[derive(Debug, Clone)]
pub(crate) enum EnforcementStatus {
    /// Normal operation - logging enabled.
    Allowed,

    /// One or more limits exceeded - contains which limits are breached.
    /// Logging stopped until limits reset.
    Restricted(Vec<LimitType>),
}

impl EnforcementStatus {
    fn is_restricted(&self) -> bool {
        matches!(self, EnforcementStatus::Restricted(_))
    }

    fn remove_limit(&mut self, limit_type: LimitType) {
        if let EnforcementStatus::Restricted(limits) = self {
            limits.retain(|&l| l != limit_type);
            if limits.is_empty() {
                *self = EnforcementStatus::Allowed;
            }
        }
    }

    fn update_limits(&mut self, updated_limits: Vec<LimitType>) {
        *self = if updated_limits.is_empty() {
            EnforcementStatus::Allowed
        } else {
            EnforcementStatus::Restricted(updated_limits)
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitType {
    Resource,
    Event,
}

/// Result from `LimitState::check_limits()` indicating enforcement actions.
#[derive(Debug, Clone)]
pub(crate) struct LimitCheckResult {
    pub(crate) allow_report: bool,
    pub(crate) limits_reached: Vec<LimitType>,
    pub(crate) new_limits: Vec<LimitType>,
}

/// Usage statistics for display to user.
#[derive(Debug, Clone)]
pub(crate) struct UsageInfo {
    pub(crate) mode: OperatingMode,
    pub(crate) resource_count: usize,
    pub(crate) resource_limit: usize,
    pub(crate) event_count: usize,
    pub(crate) event_limit: usize,
    pub(crate) time_until_reset: Duration,
    pub(crate) next_reset_hour: u32,
}

impl std::fmt::Display for UsageInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Mode: {} | Resources: {}/{} | Events: {}/{} this hour | Resets at {:02}:00 UTC ({} min)",
            self.mode,
            self.resource_count,
            self.resource_limit,
            self.event_count,
            self.event_limit,
            self.next_reset_hour,
            self.time_until_reset.num_minutes()
        )
    }
}

/// Central coordinator for license enforcement.
#[derive(Debug)]
pub(crate) struct LimitState {
    resource_tracker: ResourceTracker,
    event_tracker: EventTracker,
    enforcement_status: EnforcementStatus,
    mode: OperatingMode,
    max_resources: usize,
    max_events: usize,
}

impl LimitState {
    /// Create new license enforcer with specified limits.
    pub(crate) fn new(mode: OperatingMode, max_resources: usize, max_events: usize) -> Self {
        Self {
            resource_tracker: ResourceTracker::new(max_resources),
            event_tracker: EventTracker::new(max_events),
            enforcement_status: EnforcementStatus::Allowed,
            mode,
            max_resources,
            max_events,
        }
    }

    /// Create new license enforcer for a specific operating mode.
    pub(crate) fn for_mode(mode: OperatingMode) -> Self {
        let limits = ModeLimits::for_mode(mode);
        Self::new(mode, limits.max_resources, limits.max_events)
    }

    /// Check limits and update enforcement status after processing a report.
    ///
    /// Returns whether the current report is allowed to be processed and which limits were hit.
    #[instrument(skip(self, report))]
    pub(crate) async fn check_limits(&mut self, report: &Report) -> LimitCheckResult {
        use chrono::Utc;

        // Check for hour boundary and reset event counter if needed
        let now = Utc::now();
        let hour_changed = self.event_tracker.check_hour_boundary(now).await;

        if hour_changed {
            // If hour changed, clear event limit from enforcement status
            debug!("Hour boundary crossed, clearing event limit enforcement");
            self.enforcement_status.remove_limit(LimitType::Event);
        }

        // Extract resource IDs and track them
        let resource_ids = report.extract_resource_ids();
        let (resource_count, resource_limit_newly_hit) =
            self.resource_tracker.track_resources(resource_ids).await;

        // Track events from this report
        let (event_count, event_limit_newly_hit) = self.event_tracker.track_events(report).await;

        // Check if we were already limited before this report
        let was_already_limited = self.enforcement_status.is_restricted();

        // Build the list of currently breached limits based on tracker states
        let mut breached_limits = Vec::new();
        if self.resource_tracker.is_limited() {
            breached_limits.push(LimitType::Resource);
        }
        if self.event_tracker.is_limited() {
            breached_limits.push(LimitType::Event);
        }
        let limits_reached = breached_limits.clone();

        // Update enforcement status based on current breached limits
        self.enforcement_status.update_limits(breached_limits);

        let mut new_limits = Vec::new();

        if resource_limit_newly_hit {
            new_limits.push(LimitType::Resource);
        }
        if event_limit_newly_hit {
            new_limits.push(LimitType::Event);
        }

        // Allow report if limits haven't been reached or were just breached with this report
        let allow_report = !self.enforcement_status.is_restricted() || !was_already_limited;

        debug!(
            resource_count = resource_count,
            event_count = event_count,
            resource_limited = self.resource_tracker.is_limited(),
            event_limited = self.event_tracker.is_limited(),
            allow_report = allow_report,
            "Rate limit check completed"
        );

        LimitCheckResult {
            allow_report,
            limits_reached,
            new_limits,
        }
    }

    /// Get current usage information for display.
    ///
    /// Aggregates data from `ResourceTracker` and `EventTracker`
    pub(crate) async fn usage_info(&self) -> UsageInfo {
        use chrono::Utc;

        let now = Utc::now();
        let current_hour = now.hour();
        let next_hour = (current_hour + 1) % 24;

        // Get event count and time until reset from EventTracker
        let event_count = self.event_tracker.count().await;
        let time_until_reset = self.event_tracker.time_until_reset().await;

        UsageInfo {
            mode: self.mode,
            resource_count: self.resource_tracker.count(),
            resource_limit: self.max_resources,
            event_count,
            event_limit: self.max_events,
            time_until_reset,
            next_reset_hour: next_hour,
        }
    }
}
