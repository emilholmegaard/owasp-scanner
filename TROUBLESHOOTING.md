# Security Rule Detection Troubleshooting

## SQL Injection Detection
- Ensure detection of string concatenation in SQL queries
- Check for direct user input interpolation

## XSS Prevention Detection
- Verify detection of script tag injection
- Improve handling of JavaScript-based vulnerabilities

### Diagnostic Steps
1. Review current rule implementation
2. Add more comprehensive regex patterns
3. Enhance context-aware detection
