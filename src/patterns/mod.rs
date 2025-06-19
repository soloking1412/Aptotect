use std::path::Path;
use regex::Regex;
use crate::analyzer::{Vulnerability, Severity, Location};

pub trait SecurityPattern {
    fn name(&self) -> &'static str;
    fn check(&self, code: &str) -> Vec<Vulnerability>;
}

// Helper to track which lines are already flagged
fn flagged_lines<'a>(vulns: &'a [Vulnerability]) -> std::collections::HashSet<usize> {
    vulns.iter().map(|v| v.location.line).collect()
}

pub struct ReentrancyPattern;
pub struct IntegerOverflowPattern;
pub struct AccessControlPattern;
pub struct UncheckedArithmeticPattern;
pub struct MissingErrorHandlingPattern;
pub struct UnboundedExecutionPattern;
pub struct GenericsTypeCheckPattern;
pub struct PriceOracleManipulationPattern;
pub struct ArithmeticPrecisionPattern;
pub struct AccountRegistrationPattern;
pub struct ResourceManagementPattern;
pub struct BusinessLogicFlawPattern;
pub struct IncorrectStdFunctionPattern;

impl SecurityPattern for ReentrancyPattern {
    fn name(&self) -> &'static str {
        "Reentrancy Vulnerability"
    }

    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let external_call_pattern = Regex::new(r"coin::transfer|account::withdraw").unwrap();
        let state_change_pattern = Regex::new(r"borrow_global_mut|move_to|Table::add").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if external_call_pattern.is_match(line) {
                for j in i+1..std::cmp::min(i+5, lines.len()) {
                    if state_change_pattern.is_match(lines[j]) {
                        vulnerabilities.push(Vulnerability {
                            severity: Severity::Critical,
                            title: self.name().to_string(),
                            description: "Potential reentrancy vulnerability detected: External call followed by state change. This pattern could allow an attacker to re-enter the function before the state is updated, potentially leading to multiple withdrawals or unauthorized state modifications.".to_string(),
                            location: Location {
                                file: "contract.move".to_string(),
                                line: i + 1,
                                column: 0,
                            },
                            recommendation: "Implement the checks-effects-interactions pattern: 1) Validate all conditions first, 2) Update state variables, 3) Make external calls last. Consider using a reentrancy guard or implementing the nonReentrant modifier pattern.".to_string(),
                        });
                        break;
                    }
                }
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for IntegerOverflowPattern {
    fn name(&self) -> &'static str {
        "Integer Overflow Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let arithmetic_pattern = Regex::new(r"[=]\s*[^;\n]+\+[^;\n]+;").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if arithmetic_pattern.is_match(line) && !line.contains("assert!") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::High,
                    title: self.name().to_string(),
                    description: "Potential integer overflow detected: Arithmetic operation without overflow check. This could lead to unexpected behavior where values wrap around, potentially causing financial loss or incorrect calculations.".to_string(),
                    location: Location {
                        file: "contract.move".to_string(),
                        line: i + 1,
                        column: 0,
                    },
                    recommendation: "Add overflow checks using assert! or use safe math operations. Consider implementing a safe math library that handles overflow/underflow cases explicitly.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for UncheckedArithmeticPattern {
    fn name(&self) -> &'static str {
        "Unchecked Arithmetic Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let subtract_pattern = Regex::new(r"[=]\s*[^;\n]+-[^;\n]+;").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if subtract_pattern.is_match(line) && !line.contains("assert!") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::High,
                    title: self.name().to_string(),
                    description: "Potential unchecked arithmetic detected: Subtraction without underflow check. This could lead to unexpected behavior where values wrap around, potentially causing financial loss or incorrect calculations.".to_string(),
                    location: Location {
                        file: "contract.move".to_string(),
                        line: i + 1,
                        column: 0,
                    },
                    recommendation: "Add underflow checks using assert! or use safe math operations. Consider implementing a safe math library that handles overflow/underflow cases explicitly.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for MissingErrorHandlingPattern {
    fn name(&self) -> &'static str {
        "Missing Error Handling Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let division_pattern = Regex::new(r"[=]\s*[^;\n]+/[^;\n]+;").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if division_pattern.is_match(line) && !line.contains("assert!") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::High,
                    title: self.name().to_string(),
                    description: "Missing error handling detected: Division without zero check. This could lead to a runtime error if the divisor is zero, potentially causing the entire transaction to fail or unexpected behavior.".to_string(),
                    location: Location {
                        file: "contract.move".to_string(),
                        line: i + 1,
                        column: 0,
                    },
                    recommendation: "Add zero checks using assert! before division. Consider implementing proper error handling with custom error types and clear error messages.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for AccessControlPattern {
    fn name(&self) -> &'static str {
        "Access Control Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let state_mod_pattern = Regex::new(r"borrow_global_mut|move_to|Table::add").unwrap();
        let owner_check_pattern = Regex::new(r"assert!\(.*owner.*\)").unwrap();
        // Collect lines flagged by other patterns
        let mut flagged = std::collections::HashSet::new();
        // Integer overflow
        let overflow_vulns = IntegerOverflowPattern.check(code);
        for v in &overflow_vulns { flagged.insert(v.location.line); }
        // Unchecked arithmetic
        let unchecked_vulns = UncheckedArithmeticPattern.check(code);
        for v in &unchecked_vulns { flagged.insert(v.location.line); }
        // Missing error handling
        let error_vulns = MissingErrorHandlingPattern.check(code);
        for v in &error_vulns { flagged.insert(v.location.line); }
        // Reentrancy
        let reentrancy_vulns = ReentrancyPattern.check(code);
        for v in &reentrancy_vulns { flagged.insert(v.location.line); }
        for (i, line) in lines.iter().enumerate() {
            if state_mod_pattern.is_match(line) {
                // Only flag if not already flagged by another pattern
                if flagged.contains(&(i + 1)) {
                    continue;
                }
                let has_owner_check = lines.iter()
                    .skip(std::cmp::max(0, i as isize - 10) as usize)
                    .take(20)
                    .any(|l| owner_check_pattern.is_match(l));
                if !has_owner_check {
                    vulnerabilities.push(Vulnerability {
                        severity: Severity::High,
                        title: self.name().to_string(),
                        description: "Missing access control detected: State modification without owner check. This could allow unauthorized users to modify critical contract state, potentially leading to unauthorized access or fund theft.".to_string(),
                        location: Location {
                            file: "contract.move".to_string(),
                            line: i + 1,
                            column: 0,
                        },
                        recommendation: "Implement proper access control: 1) Add owner checks before state modifications, 2) Use role-based access control where appropriate, 3) Consider implementing a multi-signature requirement for critical operations.".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for UnboundedExecutionPattern {
    fn name(&self) -> &'static str {
        "Unbounded Execution Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let loop_pattern = Regex::new(r"while\s*\(").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if loop_pattern.is_match(line) && (line.contains("vector::length") || line.contains("len") || line.contains("user") || line.contains("input")) {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::High,
                    title: self.name().to_string(),
                    description: "Potential unbounded execution: Loop condition may be user-controlled or unbounded, leading to denial-of-service via gas exhaustion.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Limit loop iterations, use data structures that prevent unbounded growth, or add explicit iteration caps.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for GenericsTypeCheckPattern {
    fn name(&self) -> &'static str {
        "Lack of Generics Type Checking Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let generic_fn_pattern = Regex::new(r"public\s+fun\s+\w+<").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if generic_fn_pattern.is_match(line) && !line.contains("type_of") && !line.contains("assert!") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Critical,
                    title: self.name().to_string(),
                    description: "Public function with generic type parameter does not check type validity. This can allow attackers to exploit type mismatches and drain assets.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Add type checks/assertions to ensure the generic type matches the expected or whitelisted type.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for PriceOracleManipulationPattern {
    fn name(&self) -> &'static str {
        "Price Oracle Manipulation Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let price_pattern = Regex::new(r"(token_a\s*/\s*token_b|token_b\s*/\s*token_a|liquidity_ratio|price)").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if price_pattern.is_match(line) && !line.contains("oracle") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Critical,
                    title: self.name().to_string(),
                    description: "Potential price oracle manipulation: Price is calculated from on-chain ratios or manipulable sources without external validation.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Use time-weighted or external oracles, and validate price sources to prevent manipulation.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for ArithmeticPrecisionPattern {
    fn name(&self) -> &'static str {
        "Arithmetic Precision Error Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let division_pattern = Regex::new(r"/\s*\d+").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if division_pattern.is_match(line) && (line.contains("fee") || line.contains("amount") || line.contains("size")) {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Medium,
                    title: self.name().to_string(),
                    description: "Potential arithmetic precision error: Division or multiplication may cause rounding errors, allowing users to bypass fees or receive incorrect payouts.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Require minimum amounts or ensure nonzero results after division/multiplication.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for AccountRegistrationPattern {
    fn name(&self) -> &'static str {
        "Lack of Account Registration Check Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let coin_op_pattern = Regex::new(r"coin::(deposit|withdraw)").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if coin_op_pattern.is_match(line) && !line.contains("is_account_registered") && !line.contains("register") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Medium,
                    title: self.name().to_string(),
                    description: "Potential lack of account registration check: Coin operations performed without checking or registering the account, which can cause failed transactions or stuck funds.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Always check and register accounts before coin operations.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for ResourceManagementPattern {
    fn name(&self) -> &'static str {
        "Improper Resource Management Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let global_vec_pattern = Regex::new(r"struct\s+\w+\s+has\s+key\s*\{[^}]*vector<").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if global_vec_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Low,
                    title: self.name().to_string(),
                    description: "Improper resource management: Resources are stored globally instead of in user accounts, leading to ambiguous ownership and potential DoS.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Store resources in user accounts whenever possible.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for BusinessLogicFlawPattern {
    fn name(&self) -> &'static str {
        "Business Logic Flaw Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let double_action_pattern = Regex::new(r"withdraw|deposit|transfer").unwrap();
        for (i, line) in lines.iter().enumerate() {
            if double_action_pattern.is_match(line) && !line.contains("assert!") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::High,
                    title: self.name().to_string(),
                    description: "Potential business logic flaw: Function may allow repeated actions (e.g., double withdrawal) or lacks invariant checks, leading to loss of funds or protocol failure.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Carefully review and test all business logic paths, and enforce invariants with assertions.".to_string(),
                });
            }
        }
        vulnerabilities
    }
}

impl SecurityPattern for IncorrectStdFunctionPattern {
    fn name(&self) -> &'static str {
        "Incorrect Standard Function Usage Vulnerability"
    }
    fn check(&self, code: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let option_pattern = Regex::new(r"option::(borrow|extract)").unwrap();
        let mut extracted = false;
        for (i, line) in lines.iter().enumerate() {
            if line.contains("option::extract") {
                extracted = true;
            }
            if extracted && line.contains("option::borrow") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Medium,
                    title: self.name().to_string(),
                    description: "Incorrect use of standard library function: Borrowing from an Option after extracting its value can cause runtime aborts and unexpected failures.".to_string(),
                    location: Location { file: "contract.move".to_string(), line: i + 1, column: 0 },
                    recommendation: "Use each stdlib function as intended and add tests for edge cases.".to_string(),
                });
                extracted = false;
            }
        }
        vulnerabilities
    }
} 