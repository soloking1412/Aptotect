use anyhow::Result;
use std::path::Path;
use crate::patterns::{SecurityPattern, ReentrancyPattern, IntegerOverflowPattern, AccessControlPattern, UncheckedArithmeticPattern, MissingErrorHandlingPattern};
use crate::utils::read_file;

pub struct Analyzer {
    patterns: Vec<Box<dyn SecurityPattern>>,
}

impl Analyzer {
    pub fn new() -> Self {
        let patterns: Vec<Box<dyn SecurityPattern>> = vec![
            Box::new(ReentrancyPattern),
            Box::new(IntegerOverflowPattern),
            Box::new(AccessControlPattern),
            Box::new(UncheckedArithmeticPattern),
            Box::new(MissingErrorHandlingPattern),
        ];
        Self { patterns }
    }

    pub fn analyze_contract(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        let source = read_file(path)?;
        let mut vulnerabilities = Vec::new();

        // Run each security pattern
        for pattern in &self.patterns {
            vulnerabilities.extend(pattern.check(&source));
        }

        Ok(vulnerabilities)
    }

    pub fn analyze_directory(&self, dir: &Path) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();
        
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "move") {
                all_vulnerabilities.extend(self.analyze_contract(&path)?);
            }
        }

        Ok(all_vulnerabilities)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct Vulnerability {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: Location,
    pub recommendation: String,
}

#[derive(Debug, serde::Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, serde::Serialize)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
} 