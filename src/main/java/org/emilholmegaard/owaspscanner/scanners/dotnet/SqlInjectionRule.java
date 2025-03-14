package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.List;
import java.util.regex.Matcher;
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
    
    // Comprehensive SQL injection detection patterns
    private static final Pattern[] SQL_INJECTION_PATTERNS = new Pattern[] {
        // Direct string concatenation in SQL queries
        Pattern.compile("(?i)(string\\s+(?:query|sql)\\s*=\\s*[\"'].*?\\s*\\+\\s*\\w+)"),
        
        // SqlCommand with concatenated query
        Pattern.compile("(?i)(new\\s+SqlCommand\\([\"'].*?\\s*\\+\\s*\\w+)"),
        
        // Raw SQL methods with concatenation
        Pattern.compile("(?i)((?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync)\\([\"'].*?\\s*\\+\\s*\\w+)"),
        
        // Database ExecuteRaw methods with concatenation
        Pattern.compile("(?i)(_db\\.Database\\.ExecuteSqlRaw.*?\\+)"),
        
        // LIKE query with user input concatenation
        Pattern.compile("(?i)(LIKE\\s*[\"']%\\s*\\+\\s*\\w+\\s*\\+\\s*%[\"'])"),
        
        // Generic string concatenation near SQL keywords
        Pattern.compile("(?i)(SELECT|INSERT|UPDATE|DELETE|EXEC).*?\\+")
    };
    
    // Patterns for detecting user input or parameters
    private static final Pattern[] USER_INPUT_PATTERNS = new Pattern[] {
        Pattern.compile("(?i)(username|email|searchTerm|input)"),
        Pattern.compile("(?i)(Request\\.|Model\\.|\\[FromBody\\]|\\[FromQuery\\])"),
        Pattern.compile("(?i)(HttpContext\\.Request)")
    };
    
    // Patterns for safe SQL practices
    private static final Pattern[] SAFE_SQL_PATTERNS = new Pattern[] {
        Pattern.compile("(?i)(Parameters\\.Add|Parameters\\.AddWithValue)"),
        Pattern.compile("(?i)(new\\s+SqlParameter)"),
        Pattern.compile("(?i)(CreateParameter|AddParameter)"),
        Pattern.compile("(?i)(FromSqlInterpolated)")
    };
    
    public SqlInjectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check for SQL injection patterns
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                // Get surrounding context
                List<String> surroundingLines = context.getLinesAround(lineNumber, 5);
                String surroundingCode = String.join("\n", surroundingLines);
                
                // Check for user input
                boolean hasUserInput = hasUserInput(line, surroundingCode);
                
                // Check for safe SQL practices
                boolean hasSafeSqlPractices = hasSafeSqlPractices(surroundingCode);
                
                // Vulnerability exists if user input is present and no safe practices are used
                if (hasUserInput && !hasSafeSqlPractices) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Checks if the line or surrounding code contains user input indicators.
     */
    private boolean hasUserInput(String line, String surroundingCode) {
        for (Pattern pattern : USER_INPUT_PATTERNS) {
            if (pattern.matcher(line).find() || pattern.matcher(surroundingCode).find()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Checks if the surrounding code uses safe SQL practices.
     */
    private boolean hasSafeSqlPractices(String surroundingCode) {
        for (Pattern pattern : SAFE_SQL_PATTERNS) {
            if (pattern.matcher(surroundingCode).find()) {
                return true;
            }
        }
        return false;
    }
}
