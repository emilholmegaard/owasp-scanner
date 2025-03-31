package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Rule to check for secure session management in .NET applications.
 */
@Component
public class SessionManagementRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-008";
    private static final String DESCRIPTION = "Insecure session management";
    private static final String SEVERITY = "MEDIUM";
    private static final String REMEDIATION = "Configure sessions with secure settings: HttpOnly, Secure flags, and appropriate "
            +
            "SameSite attribute. Use appropriate session timeout and consider anti-CSRF tokens.";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#asp-net-session-security";

    private static final Pattern PATTERN = Pattern
            .compile("(?i)Session|Cookie|HttpOnly|SameSite|CookieOptions|UseCookiePolicy");

    // Secure cookie configuration patterns
    private static final Pattern SECURE_COOKIE_PATTERN = Pattern.compile(
            "(?i)HttpOnly\\s*=\\s*true|Secure\\s*=\\s*true|" +
                    "SameSite\\s*=\\s*(Strict|Lax)|" +
                    "\\.RequireHttps|" +
                    "CookieSecure\\.Always|" +
                    "CookieHttpOnly\\.Always");

    // Session timeout configuration
    private static final Pattern SESSION_TIMEOUT_PATTERN = Pattern.compile(
            "(?i)ExpireTimeSpan|SlidingExpiration|Cookie\\.MaxAge|" +
                    "SessionOptions\\.IdleTimeout|" +
                    "TimeSpan\\.FromMinutes|" +
                    "options\\.ExpireTimeSpan");

    /**
     * Creates a new SessionManagementRule.
     */
    public SessionManagementRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }

    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if this line deals with session or cookie configuration
        if (!isSessionRelated(line)) {
            return false;
        }

        // Get file content for analysis
        String fileContent = String.join("\n", context.getFileContent());

        // Check for secure cookie settings
        boolean hasSecureCookieSettings = SECURE_COOKIE_PATTERN.matcher(fileContent).find();

        // Check for session timeout configuration
        boolean hasSessionTimeout = SESSION_TIMEOUT_PATTERN.matcher(fileContent).find();

        // Check for global cookie policy setup
        boolean hasGlobalCookiePolicy = fileContent.contains("services.Configure<CookiePolicyOptions>") ||
                fileContent.contains("app.UseCookiePolicy") ||
                fileContent.contains("services.AddSession");

        // If global cookie policy is configured, we assume it's secure
        if (hasGlobalCookiePolicy) {
            return false;
        }

        // If it's a direct session/cookie usage without security settings, flag it
        if (line.matches("(?i).*\\.Session.*|.*Cookie.*|.*options\\.Cookie.*")) {
            // Only report violation if no secure settings are found
            return !hasSecureCookieSettings || !hasSessionTimeout;
        }

        return false;
    }

    /**
     * Determines if a line is related to session management functionality.
     */
    private boolean isSessionRelated(String line) {
        return line.matches("(?i).*\\.Session.*|.*Cookie.*|.*HttpOnly.*|.*SameSite.*|" +
                ".*CookieOptions.*|.*UseCookiePolicy.*|.*AddSession.*|" +
                ".*services\\.Configure<CookiePolicyOptions>.*");
    }
}
