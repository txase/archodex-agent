use crate::engine::{principal::Principal, report::Report};

use super::{ContextMethods, PrivateContextMethods};

#[derive(Debug)]
pub(crate) struct BaseContext {
    principals: Vec<Principal>,
    report: Report,
}

impl BaseContext {
    pub(crate) fn new() -> Self {
        Self {
            principals: vec![],
            report: Report::new(),
        }
    }
}

impl PrivateContextMethods for BaseContext {
    fn principals_mut(&mut self) -> &mut Vec<Principal> {
        &mut self.principals
    }

    fn report_mut(&mut self) -> &mut Report {
        &mut self.report
    }
}

impl ContextMethods for BaseContext {
    fn principals_without_container(&self) -> &Vec<Principal> {
        &self.principals
    }

    async fn principals(&self, _container_id: Option<&String>) -> Vec<Principal> {
        self.principals.clone()
    }
}
