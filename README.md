# OWASP Scanner

A security scanner tool based on the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) that helps identify potential security vulnerabilities in your code.

![Build, Test and Release](https://github.com/emilholmegaard/owasp-scanner/workflows/Build,%20Test%20and%20Release/badge.svg)

## 🔥 Recent Improvements

The March 2025 update includes significant improvements to the .NET scanner:

- **Redesigned architecture** using the factory pattern and separate rule classes
- **Reduced false positives** with more context-aware detection logic
- **Improved rule accuracy** with better alignment to the [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- **Enhanced test coverage** with unit and integration tests
- **Factory refactoring** using HashMap and Supplier pattern for cleaner dependency management
- **Performance testing framework** to track and optimize scanner performance
- **Performance tuning configuration** to optimize scanning based on codebase size and system capabilities

## Features

- Scans code for security vulnerabilities based on OWASP guidelines
- Currently supports .NET code scanning
- Designed with extensibility in mind for future support of other technologies (Python, Java, etc.)
- Generates JSON reports with detailed findings
- Performance testing framework to measure and track scanner efficiency
- Configurable performance tuning options for different environments

## Supported Security Checks (.NET)

The scanner checks for the following security issues in .NET code:

1. **Missing HTTP Security Headers** - Ensures proper security headers are configured
2. **Insufficient Input Validation** - Checks for proper validation of user inputs
3. **SQL Injection Vulnerabilities** - Identifies potential SQL injection points
4. **Cross-Site Scripting (XSS)** - Detects XSS vulnerabilities
5. **Missing CSRF Protection** - Checks for anti-forgery token usage
6. **Insecure Configuration Settings** - Identifies plaintext secrets and insecure config
7. **Insecure Authentication** - Checks for proper password hashing and authentication
8. **Insecure Session Management** - Ensures secure cookie and session settings
9. **Improper Exception Handling** - Detects exception info leakage

## Requirements

- Java 11 or higher
- Maven for building the project

## Getting Started

### Option 1: Download the Pre-built JAR

1. Download the latest JAR file from the [Releases](https://github.com/emilholmegaard/owasp-scanner/releases) page.
2. Run it directly:
   ```bash
   java -jar owasp-scanner.jar scan /path/to/your/code
   ```

### Option 2: Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/emilholmegaard/owasp-scanner.git
   cd owasp-scanner
   ```

2. Build with Maven:
   ```bash
   mvn clean package
   ```

3. Run the scanner:
   ```bash
   java -jar target/owasp-scanner.jar scan /path/to/your/code
   ```

## Usage

Run the scanner on a directory:

```bash
java -jar owasp-scanner.jar scan /path/to/your/code
```

Specify an output file for the report:

```bash
java -jar owasp-scanner.jar scan /path/to/your/code output-report.json
```

### Performance Tuning Options

The scanner provides several command-line options for performance tuning:

#### Preset Configurations

```bash
# Fast scan mode - optimized for speed
java -jar owasp-scanner.jar scan /path/to/your/code --fast

# Thorough scan mode - optimized for completeness
java -jar owasp-scanner.jar scan /path/to/your/code --thorough
```

#### Custom Configuration Options

```bash
# Set the number of threads to use for parallel processing
java -jar owasp-scanner.jar scan /path/to/your/code --threads=8

# Set the maximum file size to process (in MB)
java -jar owasp-scanner.jar scan /path/to/your/code --max-file-size=20

# Set the maximum number of violations to collect per file
java -jar owasp-scanner.jar scan /path/to/your/code --max-violations=50

# Disable file content caching
java -jar owasp-scanner.jar scan /path/to/your/code --no-cache

# Disable parallel processing
java -jar owasp-scanner.jar scan /path/to/your/code --no-parallel

# Disable early termination (scan entire files even when violation threshold is reached)
java -jar owasp-scanner.jar scan /path/to/your/code --no-early-termination
```

You can combine these options as needed:

```bash
# Example of combining options
java -jar owasp-scanner.jar scan /path/to/your/code --fast --threads=16 --max-file-size=50
```

## Architecture

The scanner is designed with a modular architecture:

- **Core Interfaces**: Define the contract for scanners, rules, and violations
- **Scanner Engine**: Orchestrates the scanning process
- **Technology-specific Scanners**: Implement scanning logic for different technologies
- **Security Rules**: Encapsulate the logic for detecting specific vulnerabilities
- **Rule Factory**: Creates rule instances using the factory pattern and HashMap for efficient lookup
- **Configuration System**: Allows fine-tuning scanner performance for different environments

### DotNet Scanner Design

The .NET scanner uses the following design patterns:

- **Factory Pattern**: `DotNetRuleFactory` creates and manages rule instances
- **Abstract Base Class**: `AbstractDotNetSecurityRule` provides common functionality
- **Single Responsibility**: Each rule is in its own class with focused logic
- **Dependency Injection**: Rules are created through suppliers for loose coupling
- **Singleton Pattern**: Factory is a singleton for centralized rule management

### Scanner Configuration

The scanner uses a `ScannerConfig` class to encapsulate performance tuning options:

- **Parallel Processing**: Controls whether to use parallel processing for faster scanning
- **Thread Count**: Configures the number of threads to use for parallel processing
- **File Content Caching**: Controls whether to cache file content to reduce I/O operations
- **Line Length Limiting**: Prevents excessive memory usage by truncating very long lines
- **Early Termination**: Stops scanning a file once a threshold of violations is reached
- **Maximum Violations Per File**: Controls how many violations to collect per file
- **Maximum File Size**: Skips files larger than this threshold to avoid memory issues

## Performance Testing Framework

The scanner includes a performance testing framework to measure and track improvements over time. This is particularly useful when implementing optimizations to ensure they have the expected positive impact.

### Running Performance Tests

1. Generate a test dataset:
   ```bash
   ./generate-test-dataset.sh
   ```

2. Run a baseline performance test:
   ```bash
   ./benchmark.sh baseline
   ```

3. After making changes, run another test with a descriptive label:
   ```bash
   ./benchmark.sh after-optimize-regex
   ```

4. Generate a comparison report:
   ```bash
   java -cp target/owasp-scanner.jar org.emilholmegaard.owaspscanner.performance.PerformanceSummary \
     performance-results.csv baseline after-optimize-regex
   ```

### Performance Metrics Tracked

- **Execution time**: Total scan duration
- **Memory usage**: Peak and average memory consumption
- **File count**: Number of files processed
- **Violation count**: Number of security violations found
- **System metrics**: CPU cores, max heap size, etc.

### CI/CD Integration

The repository includes GitHub Actions workflows to automatically run performance tests on pull requests labeled with `performance-test`. This helps ensure that performance doesn't regress as new features are added.

To trigger a performance test on a PR:
1. Label the PR with `performance-test`
2. The workflow will run automatically and add results as a comment on the PR

### Custom Performance Tests

You can run the performance testing utility directly:

```bash
java -cp target/owasp-scanner.jar org.emilholmegaard.owaspscanner.performance.PerformanceTest \
  /path/to/test/directory output-results.csv test-label
```

## Extending the Scanner

### Adding New Rules

To add a new .NET security rule:

1. Create a class that extends `AbstractDotNetSecurityRule`
2. Implement the `checkViolation()` method with your rule's logic
3. Register the rule in `DotNetRuleFactory`:
   ```java
   ruleSuppliers.put("DOTNET-SEC-XXX", YourNewRule::new);
   ```

### Adding Support for New Technologies

To add support for a new technology (e.g., Python, Java):

1. Implement the `SecurityScanner` interface for the new technology
2. Define technology-specific security rules
3. Create a rule factory for the new technology
4. Register the new scanner with the engine

## Running Tests

To run the test suite:

```bash
mvn test
```

This will execute all unit and integration tests.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) for the security guidelines
- All contributors and maintainers

## Future Plans

- Add support for Python, Java, JavaScript, and other technologies
- Implement more sophisticated code analysis
- Add CI/CD integration capabilities
- Support custom rule definitions
- Further optimize scanner performance
