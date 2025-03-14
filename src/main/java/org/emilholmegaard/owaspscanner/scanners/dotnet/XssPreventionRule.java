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
    
    private static final Pattern PATTERN = 
            Pattern.compile("(?i)@Html\\.Raw|Response\\.Write|document\\.write|innerHtml|" +
                           "HtmlString|JavaScriptString|MvcHtmlString|Content\\(|return .*html");
    
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
            "HttpContext\\.Request|Form\\[|IFormFile|searchTerm|username|message|content");
    
    // JavaScript-specific XSS patterns
    private static final Pattern JAVASCRIPT_XSS_PATTERN = Pattern.compile(
            "(?i)var\\s+\\w+\\s*=\\s*\"<script>\"\\s*\\+|document\\.write\\(.*\\+.*\\)|" +
            "\\.innerHTML\\s*=|\\$\\(.*\\)\\.html\\(|\\$\\(.*\\)\\.append\\(");
    
    /**
     * Creates a new XssPreventionRule.
     */
    public XssPreventionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if this is a JavaScript file
        Path filePath = context.getFilePath();
        String fileName = filePath.getFileName().toString().toLowerCase();
        boolean isJavaScriptFile = fileName.endsWith(".js") || fileName.endsWith(".jsx") || fileName.endsWith(".ts");
        
        // Special handling for JavaScript files
        if (isJavaScriptFile || isScriptBlock(line, context)) {
            if (JAVASCRIPT_XSS_PATTERN.matcher(line).find() || 
                (line.contains("<script>") && line.contains("+")) ||
                (line.contains("document.write") && line.contains("+"))) {
                return true;
            }
        }
        
        // Detect common HTML generation in controllers
        if (line.contains("Content(") && line.contains("\"text/html\"") && 
           (line.contains("+") || line.contains("$"))) {
            return true;
        }
        
        // Detect Response.Write with string concatenation
        if (line.contains("Response.Write(") && 
           (line.contains("+") || line.contains("$"))) {
            return true;
        }
        
        // Detect @Html.Raw usage
        if (line.contains("@Html.Raw")) {
            return true;
        }
        
        // Detect document.write
        if (line.contains("document.write") && line.contains("+")) {
            return true;
        }
        
        // Detect innerHtml assignment
        if (line.contains("innerHtml") && line.contains("=")) {
            return true;
        }
        
        // Check for potentially unsafe pattern with common variable names
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
    
    /**
     * Determines if the code is within a script block.
     */
    private boolean isScriptBlock(String line, RuleContext context) {
        // Check if this line is in a script block by looking at surrounding context
        String surroundingCode = String.join("\n", context.getLinesAround(context.getFileContent().indexOf(line), 5));
        return surroundingCode.contains("<script>") || surroundingCode.contains("<script ");
    }
}