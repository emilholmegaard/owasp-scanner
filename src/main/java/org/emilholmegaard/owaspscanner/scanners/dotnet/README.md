# .NET Security Scanner Rules

This package contains the implementation of security scanning rules for .NET applications based on the [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html).

## Architecture

The implementation uses the following design patterns:

1. **Factory Pattern**: `DotNetRuleFactory` creates and manages rule instances.
2. **Abstract Base Class**: `AbstractDotNetSecurityRule` provides common functionality for all rules.
3. **Single Responsibility**: Each rule is implemented in its own class with focused logic.

## Rules Implemented

The scanner covers the following security areas from the OWASP .NET Security Cheat Sheet:

1. **HTTP Security Headers** (`HttpSecurityHeadersRule`): Checks for secure HTTP header configuration.
2. **Input Validation** (`InputValidationRule`): Ensures proper validation of user inputs.
3. **SQL Injection Prevention** (`SqlInjectionRule`): Detects potential SQL injection vulnerabilities.
4. **XSS Prevention** (`XssPreventionRule`): Identifies cross-site scripting vulnerabilities.
5. **CSRF Protection** (`CsrfProtectionRule`): Verifies anti-forgery token usage.
6. **Secure Configuration** (`SecureConfigurationRule`): Checks for secure storage of sensitive settings.
7. **Authentication** (`AuthenticationRule`): Ensures secure authentication practices.
8. **Session Management** (`SessionManagementRule`): Checks for secure session configuration.
9. **Exception Handling** (`ExceptionHandlingRule`): Verifies proper exception handling practices.

## False Positive Reduction

Each rule has been designed with strategies to reduce false positives:

- Context-aware analysis (looking at surrounding code)
- Recognition of framework-specific security implementations
- Multiple detection strategies per rule
- Awareness of global security configurations

## Adding New Rules

To add a new rule:

1. Create a new class extending `AbstractDotNetSecurityRule`
2. Implement the `checkViolation()` method with rule-specific logic
3. Register the rule in `DotNetRuleFactory.createAllRules()`

## Usage

The scanner is used automatically when analyzing .NET projects. The main `DotNetScanner` class loads the rules via the factory and applies them to each file.

```java
// Example usage
SecurityScanner scanner = new DotNetScanner();
List<SecurityViolation> violations = scanner.scanFile(path);
```
