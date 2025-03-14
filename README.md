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

## Features

- Scans code for security vulnerabilities based on OWASP guidelines
- Currently supports .NET code scanning
- Designed with extensibility in mind for future support of other technologies (Python, Java, etc.)
- Generates JSON reports with detailed findings

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

## Architecture

The scanner is designed with a modular architecture:

- **Core Interfaces**: Define the contract for scanners, rules, and violations
- **Scanner Engine**: Orchestrates the scanning process
- **Technology-specific Scanners**: Implement scanning logic for different technologies
- **Security Rules**: Encapsulate the logic for detecting specific vulnerabilities
- **Rule Factory**: Creates rule instances using the factory pattern and HashMap for efficient lookup

### DotNet Scanner Design

The .NET scanner uses the following design patterns:

- **Factory Pattern**: `DotNetRuleFactory` creates and manages rule instances
- **Abstract Base Class**: `AbstractDotNetSecurityRule` provides common functionality
- **Single Responsibility**: Each rule is in its own class with focused logic
- **Dependency Injection**: Rules are created through suppliers for loose coupling
- **Singleton Pattern**: Factory is a singleton for centralized rule management

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
