package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Rule to check for potential Cross-Site Scripting (XSS) vulnerabilities in .NET applications.
 */
public class XssPreventionRule extends AbstractDotNetSecurityRule {
    
    private static final String RULE_ID = "DOTNET-SEC-004";
    private static final String DESCRIPTION = "Potential Cross-Site Scripting (XSS) vulnerability";
    private static final String SEVERITY = "HIGH";
    private static final String REMEDIATION = 
            "Use built-in HtmlEncoder or AntiXssEncoder, set correct Content-Type and charset. " +
            "Avoid using @Html.Raw for user input and prefer @Html.Encode or automatic encoding of Razor views.";
    private static final String REFERENCE = 
            "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#xss-prevention";
    
    // Enhanced XSS detection pattern
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)" +
        "(var\\s+\\w+\\s*=\\s*[\"']<script>[\"']\\s*\\+\\s*\\w+|" +  // Script tag string concatenation
        "@Html\\.Raw|Response\\.Write|document\\.write|" +  // Unsafe output methods
        "innerHTML\\s*=|" +  // Direct innerHTML assignment
        "\\+\\s*userInput|" +  // Direct user input concatenation
        "Content\\(.*[\"']text/html[\"'].*\\+)");  // Unsafe HTML content generation
    
    // Pattern for safe encoding
    private static final Pattern SAFE_ENCODING_PATTERN = Pattern.compile(
        "(?i)HtmlEncoder\\.Encode|" +
        "HttpUtility\\.HtmlEncode|" +
        "@Html\\.Encode");
    
    public XssPreventionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, XSS_PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if line contains XSS-related pattern
        if (XSS_PATTERN.matcher(line).find()) {
            // Additional context check
            String surroundingCode = String.join("\n", context.getLinesAround(lineNumber, 5));
            
            // Check for lack of safe encoding 
            boolean isSafelyEncoded = SAFE_ENCODING_PATTERN.matcher(surroundingCode).find();
            
            return !isSafelyEncoded;
        }
        
        return false;
    }
}
