//! License enforcement for Archodex Agent
//!
//! This module enforces usage limits based on your license key.
//!
//! ## Operating Modes
//! For all modes:
//! - When limits are exceeded, logging pauses until reset
//! - Events reset hourly
//!
//! **Standalone Mode** (no license key):
//! - Limited resources and events suitable for evaluation
//!
//! **Licensed Modes** (with valid license key):
//! - Limits and capabilities determined by your plan
//!
//! ## License Compliance
//!
//! The software is distributed under the Fair Core License (FCL-1.0-MIT), which
//! prohibits circumventing license functionality. Disabling, modifying, or
//! circumventing this module violates the software license (see LICENSE.md lines 55-63).
//!
//! ## How It Works
//!
//! When the agent starts, it checks for a valid license key. If present, it
//! applies your subscription tier's limits. Otherwise, it operates in Standalone
//! mode with evaluation limits.
//!
//! ## Technical Integration
//!
//! This module integrates at `src/network.rs` and `src/main.rs`. All enforcement
//! logic is isolated here for Fair Core License compliance clarity.
//!
//! For production use, get a license at: <https://archodex.com/pricing>

pub(crate) mod event_tracker;
pub(crate) mod messages;
pub(crate) mod resource_tracker;
pub(crate) mod state;

pub(crate) use messages::{EVENT_LIMIT_CTA, RESOURCE_LIMIT_CTA};
pub(crate) use state::{LimitState, LimitType, OperatingMode};
