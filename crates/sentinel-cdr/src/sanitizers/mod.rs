pub mod pdf;
pub mod openxml;
pub mod image;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisarmReportItem {
    pub element_type: String,
    pub location_path: String,
    pub action_taken: String,
    pub severity: String,
}

impl DisarmReportItem {
    pub fn new(element_type: impl Into<String>, location_path: impl Into<String>, action_taken: impl Into<String>) -> Self {
        Self {
            element_type: element_type.into(),
            location_path: location_path.into(),
            action_taken: action_taken.into(),
            severity: "HIGH".to_string(),
        }
    }
}
