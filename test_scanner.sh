#!/bin/bash

echo "Building the scanner..."
cargo build

echo -e "\nTesting with a single file..."
cargo run --bin aptotect -- -p tests/test_contract.move

echo -e "\nTesting with JSON output..."
cargo run --bin aptotect -- -p tests/test_contract.move -f json

echo -e "\nTesting with a directory..."
cargo run --bin aptotect -- -p tests/ 