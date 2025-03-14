# OWASP Scanner

A security scanner tool based on the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) that helps identify potential security vulnerabilities in your code.

![Build, Test and Release](https://github.com/emilholmegaard/owasp-scanner/workflows/Build,%20Test%20and%20Release/badge.svg)

## Features

- Scans code for security vulnerabilities based on OWASP guidelines
- Currently supports .NET code scanning
- Designed with extensibility in mind for future support of other technologies (Python, Java, etc.)
- Generates JSON reports with detailed findings

## Supported Security Checks (.NET)

The scanner currently checks for the following security issues in .NET code:

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

This architecture allows for easy extension to support additional technologies in the future.

## Extending the Scanner

To add support for a new technology (e.g., Python, Java):

1. Implement the `SecurityScanner` interface for the new technology
2. Define technology-specific security rules
3. Register the new scanner with the engine

## CI/CD Pipeline

This project uses GitHub Actions for continuous integration and deployment:

- **Build & Test**: Runs on every push and pull request to verify the code
- **Release**: Creates a new release with the JAR file when changes are pushed to the main branch

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