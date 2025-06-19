 # Aptotect: Move Smart Contract Security Scanner
## Grant Application Demo

### Introduction
Aptotect is a specialized security scanner for Move smart contracts, designed to detect common vulnerabilities and security issues in Move code. This tool helps developers write more secure smart contracts by identifying potential security risks early in the development process.

### Key Features
1. **Multiple Vulnerability Detection**
   - Reentrancy vulnerabilities
   - Integer overflow/underflow
   - Access control issues
   - Unchecked arithmetic operations
   - Missing error handling

2. **Flexible Output Formats**
   - Human-readable text output
   - JSON format for integration
   - Detailed vulnerability reports

3. **Easy to Use**
   - Simple command-line interface
   - Support for single files and directories
   - Clear vulnerability descriptions and recommendations

### Demo Walkthrough

#### 1. Installation
```bash
cargo install --path .
```

#### 2. Basic Usage
```bash
# Scan a single file
aptotect -p path/to/contract.move

# Scan with JSON output
aptotect -p path/to/contract.move -f json

# Scan a directory
aptotect -p path/to/directory
```

#### 3. Example Output
```
Aptotect v0.1.0
Analyzing: tests/test_contract.move

[HIGH] Access Control Vulnerability
Location: contract.move:13
Description: Missing access control: State modification without owner check
Recommendation: Add owner checks before state modifications

Summary: 6 vulnerabilities found
```

### Technical Implementation
1. **Pattern-Based Detection**
   - Regular expression-based pattern matching
   - Extensible pattern system
   - Severity-based classification

2. **Core Components**
   - Analyzer: Main scanning engine
   - Patterns: Vulnerability detection rules
   - Utilities: File handling and output formatting

3. **Security Patterns**
   - ReentrancyPattern
   - IntegerOverflowPattern
   - AccessControlPattern
   - UncheckedArithmeticPattern
   - MissingErrorHandlingPattern

### Future Roadmap
1. **Enhanced Detection**
   - More vulnerability patterns
   - Improved pattern matching
   - False positive reduction

2. **Integration Features**
   - CI/CD pipeline integration
   - IDE plugins
   - API for programmatic use

3. **Advanced Features**
   - Custom pattern definitions
   - Fix suggestions
   - Historical analysis

### Conclusion
Aptotect provides a solid foundation for Move smart contract security scanning. Its modular design allows for easy extension and integration, making it a valuable tool for the Move ecosystem.

### Contact
For more information or to contribute:
- GitHub: [Aptotect Repository]
- Email: [Your Contact Email]