pub mod analyzer;
pub mod patterns;
pub mod utils;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_reentrancy_detection() {
        let analyzer = analyzer::Analyzer::new();
        let test_file = Path::new("tests/test_contract.move");
        let vulnerabilities = analyzer.analyze_contract(test_file).unwrap();
        
        // TODO: Add assertions for reentrancy detection
    }

    #[test]
    fn test_integer_overflow_detection() {
        let analyzer = analyzer::Analyzer::new();
        let test_file = Path::new("tests/test_contract.move");
        let vulnerabilities = analyzer.analyze_contract(test_file).unwrap();
        
        // TODO: Add assertions for integer overflow detection
    }

    #[test]
    fn test_access_control_detection() {
        let analyzer = analyzer::Analyzer::new();
        let test_file = Path::new("tests/test_contract.move");
        let vulnerabilities = analyzer.analyze_contract(test_file).unwrap();
        
        // TODO: Add assertions for access control detection
    }
} 