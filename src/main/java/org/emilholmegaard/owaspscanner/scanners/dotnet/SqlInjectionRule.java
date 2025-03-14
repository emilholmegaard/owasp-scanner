package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.regex.Pattern;

/**
 * Rule to detect potential SQL Injection vulnerabilities in .NET applications.
 */
public class SqlInjectionRule extends AbstractDotNetSecurityRule {
    
    private static final String RULE_ID = "DOTNET-SEC-003";
    private static final String DESCRIPTION = "Potential SQL Injection vulnerability";
    private static final String SEVERITY = "CRITICAL";
    private static final String REMEDIATION = 
            "Use parameterized queries, ORMs, or stored procedures instead of string concatenation. " +
            "For Entity Framework, use LINQ queries. With ADO.NET, always use SqlParameter objects.";
    private static final String REFERENCE = 
            "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#sql-injection";
    
    // Comprehensive SQL injection detection pattern
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "(?i)(" +
        "\\+\\s*[\\w.]+\\s*\\+|" +  // String concatenation
        "FromSqlRaw\\(.*\\+|" +  // Entity Framework raw SQL with concatenation
        "ExecuteSqlRaw(Async)?\\(.*\\+|" +  // ExecuteSqlRaw methods
        "SqlCommand\\(.*\\+|" +  // SqlCommand with concatenation
        "LIKE\\s*'%\\s*\\+\\s*\\w+\\s*\\+\\s*%'|" +  // LIKE query with concatenation
        "WHERE.*=\\s*'.*\\+|" +  // Generic WHERE clause with concatenation
        "string\\s+query\\s*=.*LIKE.*\\+)" // Query string with LIKE and concatenation
    );
    
    // Pattern to identify user input variables
    private static final Pattern USER_INPUT_PATTERN = Pattern.compile(
        "(?i)(username|email|searchTerm|input)"
    );
    
    public SqlInjectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, SQL_INJECTION_PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Detect SQL injection pattern
        if (SQL_INJECTION_PATTERN.matcher(line).find()) {
            // Check for user input
            boolean hasUserInput = USER_INPUT_PATTERN.matcher(line).find();
            
            // Check if it's a LIKE query with concatenation
            boolean isLikeQueryWithConcatenation = 
                line.contains("LIKE") && 
                line.contains("'%") && 
                line.contains("+") && 
                line.contains("%'");
            
            // Check for safe practices
            boolean hasSafeParameters = 
                line.contains("Parameters.AddWithValue") ||
                line.contains("FromSqlInterpolated") ||
                line.contains(".Where(") ||
                line.contains(".FirstOrDefault(");
            
            // Flag as vulnerability if user input is present and no safe practices are used
            return (hasUserInput || isLikeQueryWithConcatenation) && !hasSafeParameters;
        }
        
        return false;
    }
}
