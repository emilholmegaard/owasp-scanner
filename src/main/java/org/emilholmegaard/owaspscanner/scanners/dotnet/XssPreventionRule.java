package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

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
    
    // Comprehensive XSS detection pattern with modified bounded quantifiers to prevent catastrophic backtracking
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)" +
        "(Content\\\\(.*?[\\\"']text/html[\\\"'].*?\\\\+.*?\\\\)|" +  // Using non-greedy quantifiers
        "@Html\\\\.Raw|Response\\\\.Write|document\\\\.write|" +  // Unchanged - no unbounded quantifiers
        "innerHTML\\\\s*=|" +  // Unchanged - no unbounded quantifiers
        "\\\\+\\\\s*[\\\\w.]{1,30}\\\\s*\\\\+|" +  // Bounded to 30 chars
        "string\\\\.Format\\\\(.*?%s.*?\\\\)|" +  // Using non-greedy quantifiers
        "HtmlString|MvcHtmlString|" +  // Unchanged - no unbounded quantifiers
        "return\\\\s+Content\\\\(.*?<.*?\\\\+.*?>.*?\\\\))"  // Using non-greedy quantifiers
    );
    
    // Pattern for user input detection
    private static final Pattern USER_INPUT_PATTERN = Pattern.compile(
        "(?i)(message|title|body|content|userInput|Request\\\\.|Model\\\\.|\\\\[FromBody\\\\]|\\\\[FromQuery\\\\])"
    );
    
    // Pattern for safe encoding
    private static final Pattern SAFE_ENCODING_PATTERN = Pattern.compile(
        "(?i)HtmlEncoder\\\\.Encode|" +
        "HttpUtility\\\\.HtmlEncode|" +
        "@Html\\\\.Encode|" +
        "WebUtility\\\\.HtmlEncode"
    );
    
    public XssPreventionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, XSS_PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if line contains XSS-related pattern
        if (XSS_PATTERN.matcher(line).find()) {
            // Get surrounding context
            String surroundingCode = String.join("\n", context.getLinesAround(lineNumber, 5));
            
            // Check for user input
            boolean hasUserInput = USER_INPUT_PATTERN.matcher(line).find() || 
                                   USER_INPUT_PATTERN.matcher(surroundingCode).find();
            
            // Check for safe encoding
            boolean isSafelyEncoded = SAFE_ENCODING_PATTERN.matcher(surroundingCode).find();
            
            // If user input is present and not safely encoded, flag as vulnerability
            return hasUserInput && !isSafelyEncoded;
        }
        
        return false;
    }
}