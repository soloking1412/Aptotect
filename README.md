# Aptotect: Move Smart Contract Security Scanner

Aptotect is a specialized security scanner for Move smart contracts. It helps developers and auditors identify potential vulnerabilities and security issues in Move code, making smart contract development safer and more robust.

---

## Features

- **Multiple Vulnerability Detection Patterns**
  - Reentrancy vulnerabilities
  - Integer overflow/underflow
  - Access control issues
  - Unchecked arithmetic operations
  - Missing error handling
  - Unbounded execution
  - Lack of generics type checking
  - Price oracle manipulation
  - Arithmetic precision errors
  - Lack of account registration checks
  - Improper resource management
  - Business logic flaws
  - Incorrect standard function usage

- **Flexible Output Formats**
  - Human-readable text output
  - JSON output for integration and automation

- **Easy-to-Use Command-Line Interface**
  - Scan single files or entire directories
  - Clear vulnerability descriptions and actionable recommendations

- **Detailed Reports**
  - Severity classification (Critical, High, Medium, Low, Info)
  - Grouped vulnerabilities with affected lines and recommendations

- **Extensible Pattern System**
  - Easily add new vulnerability patterns

- **CI/CD and Docker Support**
  - Ready for integration into CI/CD pipelines
  - Docker image for easy deployment

---

## Installation

### From Source

```bash
git clone https://github.com/soloking1412/aptotect.git
cd aptotect
cargo install --path .
```

### Using Docker

```bash
docker build -t soloking1412/aptotect:latest .
```

---

## Usage

### Scan a Single File

```bash
aptotect -p path/to/contract.move
```

### Scan with JSON Output

```bash
aptotect -p path/to/contract.move -f json
```

### Scan a Directory

```bash
aptotect -p path/to/directory
```

### Using Docker

```bash
docker run -v $(pwd):/app soloking1412/aptotect:latest -p /app/contracts
```

---

## Example Output

**Text Output:**
```
Aptotect v0.1.0
Analyzing: tests/test_contract.move

[HIGH] Access Control Vulnerability
Location: contract.move:13
Description: Missing access control: State modification without owner check
Recommendation: Add owner checks before state modifications

Summary: 6 vulnerabilities found
```

**JSON Output:**
```json
[
  {
    "severity": "High",
    "title": "Access Control Vulnerability",
    "description": "Missing access control: State modification without owner check",
    "location": { "file": "contract.move", "line": 13, "column": 0 },
    "recommendation": "Add owner checks before state modifications"
  }
]
```

---

## Development

### Prerequisites

- Rust 1.75 or later
- Cargo

### Build

```bash
cargo build
```

### Test

```bash
cargo test
```

### Lint

```bash
cargo clippy
```

---

## CI/CD

A GitHub Actions workflow is included to:
- Build the project
- Run tests
- Perform linting
- Create release artifacts

---

## Docker Deployment

1. Build the Docker image:
   ```bash
   docker build -t soloking1412/aptotect:latest .
   ```
2. Push to Docker Hub:
   ```bash
   docker push soloking1412/aptotect:latest
   ```

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contact

Maheswaran Velmurugan  
GitHub: [soloking1412](https://github.com/soloking1412)  
Email: maheswaranvelmurugan@gmail.com

Project Link: [https://github.com/soloking1412/aptotect](https://github.com/soloking1412/aptotect) 