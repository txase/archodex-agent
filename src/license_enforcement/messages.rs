//! Call-to-action messages displayed when license enforcement limits are exceeded.
//!

pub(crate) const RESOURCE_LIMIT_CTA: &str = "\
╔══════════════════════════════════════════════════════════════════════════════════╗
║ RESOURCE LIMIT REACHED                                                           ║
║                                                                                  ║
║ You have reached the resource limit for Standalone mode (no license key).        ║
║ The agent will stop logging.                                                     ║
║                                                                                  ║
║ To track more resources, get a license at:                                       ║
║ https://archodex.com/pricing                                                     ║
╚══════════════════════════════════════════════════════════════════════════════════╝";

pub(crate) const EVENT_LIMIT_CTA: &str = "\
╔══════════════════════════════════════════════════════════════════════════════════╗
║ EVENT LIMIT REACHED                                                              ║
║                                                                                  ║
║ You have reached the events per hour limit for Standalone mode (no license key). ║
║ Logging will automatically resume at the start of the next hour.                 ║
║                                                                                  ║
║ To track more events per hour, get a license at:                                 ║
║ https://archodex.com/pricing                                                     ║
╚══════════════════════════════════════════════════════════════════════════════════╝";
