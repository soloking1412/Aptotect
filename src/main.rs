use clap::Parser;
use std::path::PathBuf;
use anyhow::Result;
use crate::analyzer::Analyzer;
use serde_json;

#[derive(Parser, Debug)]
#[command(name = "Aptotect", author, version = "0.1.0", about = "Aptotect: Security scanner for Move smart contracts", long_about = None)]
struct Args {
    /// Path to the Move source file or directory to analyze
    #[arg(short, long)]
    path: PathBuf,

    /// Output format (json or text)
    #[arg(short, long, default_value = "text")]
    format: String,
}

mod analyzer;
mod patterns;
mod utils;

fn format_vulnerabilities(vulnerabilities: Vec<crate::analyzer::Vulnerability>, format: &str) -> String {
    match format {
        "json" => serde_json::to_string_pretty(&vulnerabilities).unwrap_or_else(|_| "Error formatting JSON".to_string()),
        "text" => {
            let mut output = String::new();
            
            // Group vulnerabilities by type
            let mut grouped_vulns: std::collections::HashMap<String, Vec<&crate::analyzer::Vulnerability>> = std::collections::HashMap::new();
            for vuln in &vulnerabilities {
                grouped_vulns.entry(vuln.title.clone()).or_default().push(vuln);
            }

            // Print header
            output.push_str(&format!(
                "╔════════════════════════════════════════════════════════════╗\n\
                 ║                      Aptotect v0.1.0                      ║\n\
                 ╚════════════════════════════════════════════════════════════╝\n\n"
            ));

            // Print each group
            for (title, vulns) in grouped_vulns.iter() {
                let severity = &vulns[0].severity;
                let severity_color = match severity {
                    crate::analyzer::Severity::Critical => "\x1b[31m", // Red
                    crate::analyzer::Severity::High => "\x1b[31m",     // Red (High)
                    crate::analyzer::Severity::Medium => "\x1b[33m",   // Yellow (Medium)
                    crate::analyzer::Severity::Low => "\x1b[32m",      // Green (Low)
                    crate::analyzer::Severity::Info => "\x1b[37m",     // White
                };

                // Print severity and title
                output.push_str(&format!(
                    "{}[{:?}] {}\x1b[0m\n",
                    severity_color,
                    severity,
                    title
                ));

                // For Access Control, group all locations together
                if title == "Access Control Vulnerability" {
                    output.push_str("\nAffected Lines:\n");
                    for vuln in vulns {
                        output.push_str(&format!(
                            "  • file://{}:{}\n",
                            vuln.location.file,
                            vuln.location.line
                        ));
                    }
                    output.push_str("\n");
                } else {
                    // For other vulnerabilities, show all locations first
                    output.push_str("\nAffected Lines:\n");
                    for vuln in vulns {
                        output.push_str(&format!(
                            "  • file://{}:{}\n",
                            vuln.location.file,
                            vuln.location.line
                        ));
                    }
                    output.push_str("\n");
                }

                // Print description, impact, and recommendation (only once per group)
                output.push_str(&format!(
                    "Description: {}\n",
                    vulns[0].description
                ));
                output.push_str(&format!(
                    "Impact: {}\n",
                    "This vulnerability could result in significant financial loss or unauthorized access to critical functions."
                ));
                output.push_str(&format!(
                    "Recommendation: {}\n",
                    vulns[0].recommendation
                ));

                output.push_str("\n--------------------------------------------------------------------------------\n\n");
            }

            // Add summary
            output.push_str(&format!(
                "Summary: {} vulnerabilities found\n",
                vulnerabilities.len()
            ));

            output
        },
        _ => "Unsupported output format".to_string(),
    }
}

fn main() -> Result<()> {
    env_logger::init();
    
    let args = Args::parse();
    
    println!("\x1b[1;31m╔════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;31m║                      Aptotect v0.1.0                      ║\x1b[0m");
    println!("\x1b[1;31m╚════════════════════════════════════════════════════════════╝\x1b[0m");
    println!("\n\x1b[1mAnalyzing:\x1b[0m {}", args.path.display());
    
    let analyzer = Analyzer::new();
    let vulnerabilities = if args.path.is_dir() {
        analyzer.analyze_directory(&args.path)?
    } else {
        analyzer.analyze_contract(&args.path)?
    };

    let output = format_vulnerabilities(vulnerabilities, &args.format);
    println!("{}", output);
    
    Ok(())
}
