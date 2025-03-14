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
        "LIKE\\s*'%\\s*\\+|" +  // LIKE query with concatenation
        "WHERE.*=\\s*'.*\\+)" // Generic WHERE clause with concatenation
    );
    
    public SqlInjectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, SQL_INJECTION_PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Additional context check
        if (SQL_INJECTION_PATTERN.matcher(line).find()) {
            // Specific scenarios to check
            boolean hasRawSqlMethods = line.contains("FromSqlRaw") || 
                                       line.contains("ExecuteSqlRaw") ||
                                       line.contains("SqlCommand");
            
            // Check for concatenation with variables like username, email
            boolean hasUserInput = line.contains("username") || 
                                   line.contains("email") || 
                                   line.contains("searchTerm");
            
            // Exclude safe patterns
            boolean hasSafeParameters = line.contains("Parameters.AddWithValue") ||
                                        line.contains("FromSqlInterpolated") ||
                                        line.contains(".Where(") ||
                                        line.contains(".FirstOrDefault(");
            
            // Flag as vulnerability if unsafe methods are used with user input
            return hasRawSqlMethods && hasUserInput && !hasSafeParameters;
        }
        
        return false;
    }
}
