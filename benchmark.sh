#!/bin/bash

# Performance benchmark script for the OWASP Scanner
# Usage: ./benchmark.sh [label]

# Default label is the current date and time if not provided
LABEL=${1:-$(date +"%Y%m%d-%H%M%S")}
TEST_DIR="./test-dataset"
RESULTS_FILE="./performance-results.csv"

# Ensure the test dataset exists
if [ ! -d "$TEST_DIR" ]; then
  echo "Error: Test dataset directory not found: $TEST_DIR"
  echo "Please create the test dataset first. See README.md for instructions."
  exit 1
fi

# Build the project
echo "Building project..."
mvn clean package -DskipTests

if [ $? -ne 0 ]; then
  echo "Error: Build failed"
  exit 1
fi

# Run the performance test multiple times to get a more reliable average
echo "Running performance tests with label: $LABEL"
echo "This will run 3 iterations to get a reliable average..."

# Run with controlled heap size
for i in {1..3}; do
  echo "Run $i of 3..."
  java -Xmx512m -cp target/owasp-scanner.jar org.emilholmegaard.owaspscanner.performance.PerformanceTest \
    "$TEST_DIR" "$RESULTS_FILE" "$LABEL-run$i"
  
  # Add a short delay between runs
  sleep 2
done

# Generate summary
echo "Generating performance summary..."
java -cp target/owasp-scanner.jar org.emilholmegaard.owaspscanner.performance.PerformanceSummary "$RESULTS_FILE"

echo "Performance benchmark completed."
echo "Results saved to: $RESULTS_FILE"
