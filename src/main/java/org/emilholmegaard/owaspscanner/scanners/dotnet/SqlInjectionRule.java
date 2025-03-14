package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rule to detect potential SQL Injection vulnerabilities in .NET applications.
 * Focuses on reducing false positives by looking for specific patterns and contexts.
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
    
    // Main pattern for initial detection - expanded to cover more cases
    private static final Pattern PATTERN = 
            Pattern.compile("(?i)SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar|DbCommand|" +
                           "SqlDataAdapter|OleDbCommand|ExecuteSqlRaw|FromSqlRaw");
    
    // Additional patterns for deeper analysis
    private static final Pattern SQL_STRING_PATTERN = 
            Pattern.compile("(?i)string\\s+(?:sql|query|cmd|command)\\s*=\\s*");
    
    private static final Pattern SQL_QUERY_PATTERN =
            Pattern.compile("(?i)SELECT|INSERT|UPDATE|DELETE|EXEC|EXECUTE");
    
    private static final Pattern STRING_CONCAT_PATTERN = 
            Pattern.compile("(?i)\\+\\s*[\\w\\.]*|string\\.Format|\\$\"|\\$@\"|@\\$\"");
    
    private static final Pattern SAFE_PARAM_PATTERN = 
            Pattern.compile("(?i)Parameters\\.Add|Parameters\\.AddWithValue|new SqlParameter|"
                           + "\\bparam\\w*\\s*=\\s*.*Parameters\\.Add|"
                           + "CreateParameter|AddParameter");
    
    // ORM usage patterns (considered safe from SQL injection)
    private static final Pattern ORM_USAGE_PATTERN =
            Pattern.compile("(?i)\\.(Where|FirstOrDefault|SingleOrDefault|Find|Include)\\(|"
                           + "DbContext|DbSet|IQueryable|EntityFramework|"
                           + "\\bfrom\\s+\\w+\\s+in\\s+\\w+|"
                           + "repository\\.");
    
    /**
     * Creates a new SqlInjectionRule.
     */
    public SqlInjectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // If the file uses ORMs throughout and no raw SQL, we can skip detailed checks
        if (isLikelyORMUsageOnly(context.getFileContent()) && !containsSuspiciousSqlPatterns(context.getFileContent())) {
            return false;
        }
        
        // Case 1: Direct concatenation in the current line with SQL commands
        if (containsSqlCommandWithConcatenation(line)) {
            return true;
        }
        
        // Case 2: Detects SQL query strings being built with concatenation
        if (line.contains("string query = ") || line.contains("var query = ") || 
            line.contains("string sql = ") || line.contains("var sql = ")) {
            if (containsSqlQuery(line) && line.contains("+")) {
                return true;
            }
        }
        
        // Case 3: Check for SQL string building with concatenation in surrounding context
        List<String> surroundingLines = context.getLinesAround(lineNumber, 5);
        String surroundingCode = String.join("\n", surroundingLines);
        
        boolean hasSqlDeclaration = SQL_STRING_PATTERN.matcher(surroundingCode).find();
        boolean hasStringConcatenation = STRING_CONCAT_PATTERN.matcher(surroundingCode).find();
        boolean hasSqlExecution = PATTERN.matcher(surroundingCode).find() || SQL_QUERY_PATTERN.matcher(surroundingCode).find();
        boolean hasParameters = SAFE_PARAM_PATTERN.matcher(surroundingCode).find();
        
        // If we detect SQL string building with concatenation near SQL execution
        if (hasSqlExecution && hasSqlDeclaration && hasStringConcatenation && !hasParameters) {
            return true;
        }
        
        // Case 4: Check for .Execute methods with string concatenation
        if (line.matches("(?i).*Execute(Reader|NonQuery|Scalar|Command|SqlRaw).*") &&
            (line.contains("+") || line.contains("$") || line.contains("string.Format"))) {
            return !surroundingCode.contains("Parameters.Add");
        }
        
        // If we got to this point, but still have a line that contains SQL command execution
        // We'll do a deeper analysis with a wider context window
        if (line.matches("(?i).*SqlCommand.*|.*ExecuteReader.*|.*ExecuteNonQuery.*|.*ExecuteScalar.*")) {
            // Get a wider context (10 lines) to analyze the SQL generation pattern
            List<String> widerContext = context.getLinesAround(lineNumber, 10);
            String widerContextStr = String.join("\n", widerContext);
            
            // If we find that parameters are used appropriately, we'll consider it safe
            if (SAFE_PARAM_PATTERN.matcher(widerContextStr).find()) {
                return false;
            }
            
            // If we find SQL string building with potential user input
            if (SQL_STRING_PATTERN.matcher(widerContextStr).find() && 
                STRING_CONCAT_PATTERN.matcher(widerContextStr).find() &&
                widerContextStr.matches("(?i).*\\.Text.*|.*Request\\.*|.*\\[.*\\].*|.*\\+.*")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if a line contains SQL query keywords.
     */
    private boolean containsSqlQuery(String line) {
        return SQL_QUERY_PATTERN.matcher(line).find();
    }
    
    /**
     * Checks if a line contains SQL command with string concatenation.
     */
    private boolean containsSqlCommandWithConcatenation(String line) {
        return (line.contains("SqlCommand") && line.contains("+")) ||
               (line.contains("ExecuteReader") && line.contains("+")) ||
               (line.contains("ExecuteNonQuery") && line.contains("+")) ||
               (line.matches("(?i).*ExecuteSqlRaw.*\\+.*")) ||
               (line.matches("(?i).*FromSqlRaw.*\\+.*"));
    }
    
    /**
     * Detects if the file is likely using ORM throughout instead of raw SQL.
     */
    private boolean isLikelyORMUsageOnly(List<String> fileContent) {
        String fileContentStr = String.join("\n", fileContent);
        
        // Check for strong indicators of ORM usage 
        int ormMatchCount = 0;
        Matcher ormMatcher = ORM_USAGE_PATTERN.matcher(fileContentStr);
        while (ormMatcher.find()) {
            ormMatchCount++;
        }
        
        // Check for common Entity Framework patterns
        boolean hasDbSetProperties = fileContentStr.contains("DbSet<") || 
                                   fileContentStr.matches("(?i).*public\\s+DbSet<.*>.*\\{\\s*get;\\s*set;\\s*\\}.*");
        
        boolean hasDbContextInheritance = fileContentStr.matches("(?i).*class\\s+\\w+\\s*:\\s*DbContext.*");
        
        // If we have multiple ORM indicators AND not many SQL command references,
        // we can be reasonably confident the file uses primarily an ORM approach
        int sqlCommandMatches = 0;
        Matcher sqlMatcher = PATTERN.matcher(fileContentStr);
        while (sqlMatcher.find()) {
            sqlCommandMatches++;
        }
        
        return (ormMatchCount > 3 || hasDbSetProperties || hasDbContextInheritance) && 
               sqlCommandMatches <= 2;
    }
    
    /**
     * Checks for suspicious SQL patterns that might indicate raw SQL usage.
     */
    private boolean containsSuspiciousSqlPatterns(List<String> fileContent) {
        String contentStr = String.join("\n", fileContent);
        
        // Look for SQL keywords in string contexts
        return contentStr.matches("(?i).*\".*SELECT.*FROM.*\".*") ||
               contentStr.matches("(?i).*\".*INSERT INTO.*\".*") ||
               contentStr.matches("(?i).*\".*UPDATE.*SET.*\".*") ||
               contentStr.matches("(?i).*\".*DELETE FROM.*\".*");
    }
}