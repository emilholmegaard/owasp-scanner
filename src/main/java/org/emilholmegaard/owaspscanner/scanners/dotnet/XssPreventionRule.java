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
    
    private static final Pattern PATTERN = 
            Pattern.compile("(?i)@Html\\.Raw|Response\\.Write|document\\.write|innerHtml|" +
                           "HtmlString|JavaScriptString|MvcHtmlString");
    
    // Pattern for safe encoding usage
    private static final Pattern SAFE_ENCODING_PATTERN = Pattern.compile(
            "(?i)HtmlEncoder\\.Encode|JavaScriptEncoder\\.Encode|UrlEncoder\\.Encode|" +
            "HttpUtility\\.HtmlEncode|HttpUtility\\.JavaScriptStringEncode|" +
            "System\\.Net\\.WebUtility\\.HtmlEncode|" +
            "AntiXssEncoder|" +
            "@Html\\.Encode|@Html\\.DisplayFor");
    
    // Pattern for content coming from user input
    private static final Pattern USER_INPUT_PATTERN = Pattern.compile(
            "(?i)Request\\.|Model\\.|\\[FromBody\\]|\\[FromQuery\\]|" +
            "HttpContext\\.Request|Form\\[|IFormFile");
    
    /**
     * Creates a new XssPreventionRule.
     */
    public XssPreventionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if this is an immediate high-risk pattern
        boolean isHighRiskPattern = line.matches("(?i).*@Html\\.Raw\\s*\\(.*Request.*\\).*") ||
                                   line.matches("(?i).*Response\\.Write\\s*\\(.*Request.*\\).*") ||
                                   line.matches("(?i).*document\\.write\\s*\\(.*\\).*") ||
                                   (line.contains("innerHtml") && line.contains("="));
        
        if (isHighRiskPattern) {
            return true;
        }
        
        // Check for potentially unsafe pattern
        if (PATTERN.matcher(line).find()) {
            // Get surrounding context
            String surroundingCode = String.join("\n", context.getLinesAround(lineNumber, 5));
            
            // If we have unsafe pattern + user input being used, but no encoding, it's a problem
            boolean hasUserInput = USER_INPUT_PATTERN.matcher(surroundingCode).find();
            boolean hasSafeEncoding = SAFE_ENCODING_PATTERN.matcher(surroundingCode).find();
            
            return hasUserInput && !hasSafeEncoding;
        }
        
        return false;
    }
}
