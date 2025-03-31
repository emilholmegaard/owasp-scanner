package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Rule to check for proper implementation of HTTP Security Headers in .NET
 * applications.
 * Based on OWASP .NET Security Cheat Sheet.
 */
@Component
public class HttpSecurityHeadersRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-001";
    private static final String DESCRIPTION = "Missing HTTP Security Headers";
    private static final String SEVERITY = "HIGH";
    private static final String REMEDIATION = "Add appropriate security headers to HTTP responses. Consider using middleware or "
            +
            "filters to apply headers consistently across your application. Required headers include " +
            "X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#http-security-headers";
    private static final Pattern PATTERN = Pattern
            .compile("(?i)Response\\.Headers\\.Add|app\\.Use\\(|UseHsts\\(|UseCors\\(");

    /**
     * Creates a new HttpSecurityHeadersRule.
     */
    public HttpSecurityHeadersRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }

    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check for specific security headers in the entire file
        String fileContent = String.join("\n", context.getFileContent());

        boolean hasSecurityHeaders = checkForRequiredHeaders(fileContent);

        // Only flag a violation on lines related to HTTP response headers
        if (line.matches("(?i).*Response\\.Headers\\.Add.*|.*app\\.Use\\(.*|.*UseHsts\\(.*|.*UseCors\\(.*")) {
            return !hasSecurityHeaders;
        }

        return false;
    }

    private boolean checkForRequiredHeaders(String fileContent) {
        // Check for various ways security headers can be implemented in .NET

        // Check for .NET Core/5+ middleware approach
        boolean usingMiddleware = fileContent.contains("UseSecurityHeaders") ||
                fileContent.contains("app.Use(SecurityHeaders") ||
                fileContent.contains("AddSecurityHeaders");

        // Check for common security headers - more robust checking with specific header
        // names
        boolean hasXContentTypeOptions = fileContent.contains("X-Content-Type-Options") &&
                (fileContent.contains("nosniff") || fileContent.contains("\"nosniff\""));

        boolean hasXFrameOptions = fileContent.contains("X-Frame-Options") &&
                (fileContent.contains("DENY") || fileContent.contains("SAMEORIGIN"));

        boolean hasCsp = fileContent.contains("Content-Security-Policy") ||
                fileContent.contains("AddContentSecurityPolicy");

        // Check for header definition in AppBuilder extensions (common practice)
        boolean hasExtensionMethod = fileContent.contains("AddHeaderPolicies") ||
                fileContent.contains("ConfigureSecurityHeaders");

        // Check for NWebSec usage (popular security library)
        boolean usesNWebSec = fileContent.contains("NWebsec") &&
                (fileContent.contains("UseXContentTypeOptions") ||
                        fileContent.contains("UseXfo") ||
                        fileContent.contains("UseCsp"));

        return usingMiddleware || hasExtensionMethod || usesNWebSec ||
                (hasXContentTypeOptions && hasXFrameOptions && hasCsp);
    }
}
