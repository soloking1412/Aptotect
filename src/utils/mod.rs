use std::path::Path;
use anyhow::Result;

pub fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))
}

pub fn write_file(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content).map_err(|e| anyhow::anyhow!("Failed to write file: {}", e))
} 