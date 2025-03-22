package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.regex.Pattern;

/**
 * Rule to check for potential Cross-Site Scripting (XSS) vulnerabilities in
 * .NET applications.
 */
public class XssPreventionRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-004";
    private static final String DESCRIPTION = "Potential Cross-Site Scripting (XSS) vulnerability";
    private static final String SEVERITY = "HIGH";
    private static final String REMEDIATION = "Use built-in HtmlEncoder or AntiXssEncoder, set correct Content-Type and charset. "
            +
            "Avoid using @Html.Raw for user input and prefer @Html.Encode or automatic encoding of Razor views.";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#xss-prevention";

    // Comprehensive XSS detection pattern with modified bounded quantifiers to
    // prevent catastrophic backtracking
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)" +
                    "(Content\\(.*?[\"']text/html[\"'].*?\\+.*?\\)|" +
                    "@Html\\.Raw\\(.*?\\)|" + // Modified to catch full @Html.Raw() calls
                    "Response\\.Write\\(.*?\\)|" + // Modified to catch full Response.Write() calls
                    "document\\.write|" +
                    "innerHTML\\s*=|" +
                    "\\+\\s*[\\w.]{1,30}\\s*\\+|" +
                    "string\\.Format\\(.*?%s.*?\\)|" +
                    "HtmlString|MvcHtmlString|" +
                    "return\\s+Content\\(.*?<.*?\\+.*?>.*?\\))");

    // Pattern for user input detection - improved to catch more cases
    private static final Pattern USER_INPUT_PATTERN = Pattern.compile(
            "(?i)(message|title|body|content|userInput|input|Request\\.|Model\\.|\\[FromBody\\]|\\[FromQuery\\]|" +
                    "Request\\[|Form\\[|Query\\[|Params\\[)");

    // Pattern for safe encoding
    private static final Pattern SAFE_ENCODING_PATTERN = Pattern.compile(
            "(?i)HtmlEncoder\\.Encode|" +
                    "HttpUtility\\.HtmlEncode|" +
                    "@Html\\.Encode|" +
                    "WebUtility\\.HtmlEncode");

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