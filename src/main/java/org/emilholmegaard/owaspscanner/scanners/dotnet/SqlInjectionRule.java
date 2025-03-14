package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.List;
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
    
    // Enhanced SQL injection detection patterns
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "(?i)" +
        "(string\\s+query\\s*=\\s*[\"'].*%s.*[\"']\\s*\\+\\s*\\w+|" +  // Direct string concatenation in query
        "SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteSqlRaw|" +  // SQL execution methods
        "FromSqlRaw|SqlDataAdapter|DatabaseContext\\.Database\\.ExecuteSqlRaw|" +  // Raw SQL method calls
        "@?\\$?\".*SELECT.*FROM.*\\+.*\"|" +  // SQL strings with concatenation
        "@?\\$?\".*WHERE.*LIKE.*%|" +  // LIKE condition with potential injection
        "string\\.Format\\(.*%s.*,\\s*\\w+\\))"  // String formatting with potential injection
    );
    
    // Pattern to detect safe parameter usage
    private static final Pattern SAFE_PARAM_PATTERN = Pattern.compile(
        "(?i)Parameters\\.Add|" +
        "Parameters\\.AddWithValue|" +
        "new SqlParameter|" +
        "CreateParameter|" +
        "@param|" +
        "DbParameter"
    );
    
    // Pattern to detect ORM/safe SQL generation
    private static final Pattern SAFE_ORM_PATTERN = Pattern.compile(
        "(?i)LINQ\\.Where|" +
        "FirstOrDefault|" +
        "SingleOrDefault|" +
        "Find\\(|" +
        "Include\\(|" +
        "DbContext|" +
        "DbSet|" +
        "EntityFrameworkCore|" +
        "repository\\."
    );
    
    public SqlInjectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, SQL_INJECTION_PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check for potential SQL injection pattern
        if (SQL_INJECTION_PATTERN.matcher(line).find()) {
            // Get surrounding context
            List<String> surroundingLines = context.getLinesAround(lineNumber, 5);
            String surroundingCode = String.join("\n", surroundingLines);
            
            // Check if safe parameter usage exists
            boolean hasSafeParams = SAFE_PARAM_PATTERN.matcher(surroundingCode).find();
            
            // Check if ORM/safe SQL methods are used
            boolean hasOrmUsage = SAFE_ORM_PATTERN.matcher(surroundingCode).find();
            
            // If no safe parameter usage or ORM methods, it's a potential vulnerability
            return !(hasSafeParams || hasOrmUsage);
        }
        
        return false;
    }
}
