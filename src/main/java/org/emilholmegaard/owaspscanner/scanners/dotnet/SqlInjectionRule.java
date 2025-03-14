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
        "(?i)" +
        "(FromSqlRaw\\([\"'].*\\+.*[\"']\\)|" +  // Entity Framework raw SQL with concatenation
        "ExecuteSqlRaw(Async)?\\([\"'].*\\+.*[\"']\\)|" +  // ExecuteSqlRaw methods
        "SqlCommand\\(.*\\+.*\\)|" +  // SqlCommand with concatenation
        "string\\.Format\\(.*SELECT.*\\+.*\\)|" +  // String formatting with SQL
        "CreateCommand\\(\\)\\.CommandText\\s*=.*\\+|" +  // Setting command text with concatenation
        "new\\s+OleDbCommand\\(.*\\+.*\\)|" +  // OleDb command with concatenation
        "DbCommand\\.CreateCommand\\(\\)\\.CommandText\\s*=.*\\+|" +  // DbCommand with concatenation
        "ExecuteReader\\(\\)\\s*\\..*\\s*=.*\\+|" +  // Execute reader with concatenation
        "Username\\s*=\\s*[\"'].*\\s*\\+.*[\"']|" +  // Direct user input in queries
        "Email\\s*=\\s*[\"'].*\\s*\\+.*[\"']|" +  // Email concatenation
        "string\\s+query\\s*=\\s*[\"'].*\\s*\\+.*[\"'])"  // Direct query string concatenation
    );
    
    // Pattern for potentially unsafe method calls
    private static final Pattern UNSAFE_METHOD_PATTERN = Pattern.compile(
        "(?i)(ExecuteNonQuery|ExecuteScalar|ExecuteReader|FromSqlRaw|ExecuteSqlRaw)"
    );
    
    // Pattern for user input or parameter detection
    private static final Pattern USER_INPUT_PATTERN = Pattern.compile(
        "(?i)(username|email|searchTerm|Request\\.|Model\\.|\\[FromBody\\]|\\[FromQuery\\])"
    );
    
    // Pattern to detect safe parameter usage
    private static final Pattern SAFE_PARAM_PATTERN = Pattern.compile(
        "(?i)Parameters\\.Add|" +
        "Parameters\\.AddWithValue|" +
        "new SqlParameter|" +
        "CreateParameter|" +
        "DbParameter\\..*=|" +
        "AddWithValue\\("
    );
    
    // Pattern for safe ORM methods
    private static final Pattern SAFE_ORM_PATTERN = Pattern.compile(
        "(?i)Where\\(|" +
        "FirstOrDefault\\(|" +
        "SingleOrDefault\\(|" +
        "Find\\(|" +
        "Include\\(|" +
        "DbContext|" +
        "DbSet|" +
        "EntityFrameworkCore|" +
        "FromSqlInterpolated"
    );
    
    public SqlInjectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, SQL_INJECTION_PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check for SQL injection pattern
        if (SQL_INJECTION_PATTERN.matcher(line).find()) {
            // Get surrounding context
            String surroundingCode = String.join("\n", context.getLinesAround(lineNumber, 5));
            
            // Check for potentially unsafe method calls
            boolean hasUnsafeMethod = UNSAFE_METHOD_PATTERN.matcher(line).find();
            
            // Check for user input
            boolean hasUserInput = USER_INPUT_PATTERN.matcher(line).find() || 
                                   USER_INPUT_PATTERN.matcher(surroundingCode).find();
            
            // Check for safe parameter usage
            boolean hasSafeParams = SAFE_PARAM_PATTERN.matcher(surroundingCode).find();
            
            // Check for safe ORM methods
            boolean hasSafeOrm = SAFE_ORM_PATTERN.matcher(surroundingCode).find();
            
            // Flag as vulnerability if:
            // 1. Unsafe method is used
            // 2. User input is present
            // 3. No safe parameters or ORM methods are used
            return hasUnsafeMethod && hasUserInput && !(hasSafeParams || hasSafeOrm);
        }
        
        return false;
    }
}
