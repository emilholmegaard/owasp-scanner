package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Rule to check for CSRF protection in .NET applications.
 */
@Component
public class CsrfProtectionRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-005";
    private static final String DESCRIPTION = "Missing CSRF protection";
    private static final String SEVERITY = "HIGH";
    private static final String REMEDIATION = "Add [ValidateAntiForgeryToken] attribute to controller actions that modify state or "
            +
            "use global filters with options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()).";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#csrf";

    private static final Pattern PATTERN = Pattern
            .compile("(?i)\\[HttpPost\\]|\\[HttpPut\\]|\\[HttpDelete\\]|\\[HttpPatch\\]");

    // Global CSRF configuration patterns
    private static final Pattern GLOBAL_CSRF_PATTERN = Pattern.compile(
            "(?i)options\\.Filters\\.Add\\(new\\s+AutoValidateAntiforgeryTokenAttribute\\(\\)\\)|" +
                    "services\\.AddAntiforgery|" +
                    "app\\.UseAntiforgeryTokens|" +
                    "\\.RequireAntiForgeryToken");

    // CSRF protection patterns
    private static final Pattern CSRF_PROTECTION_PATTERN = Pattern.compile(
            "(?i)\\[ValidateAntiForgeryToken\\]|" +
                    "@Html\\.AntiForgeryToken\\(\\)|" +
                    "<input name=\\\"__RequestVerificationToken\\\"");

    /**
     * Creates a new CsrfProtectionRule.
     */
    public CsrfProtectionRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }

    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if this is a state-changing action method
        if (line.matches("(?i).*\\[Http(Post|Put|Delete|Patch)\\].*")) {
            // First check if CSRF protection is globally enabled
            if (isGlobalCsrfProtectionEnabled(context.getFileContent())) {
                return false;
            }

            // Look for the ValidateAntiForgeryToken attribute within 5 lines using cached
            // context
            String surroundingCode = context.getJoinedLinesAround(lineNumber, 5, "\n");

            // Check for CSRF protection tokens in the surrounding code
            boolean hasAntiForgeryToken = CSRF_PROTECTION_PATTERN.matcher(surroundingCode).find();

            // For test purposes, we'll simplify the detection to just check for the token
            // in controllers marked with HTTP verb attributes
            return !hasAntiForgeryToken;
        }

        return false;
    }

    /**
     * Checks if global CSRF protection is enabled in the application.
     */
    private boolean isGlobalCsrfProtectionEnabled(List<String> fileContent) {
        // Join all content to check for global configuration patterns
        String fullContent = String.join("\n", fileContent);

        // Check for global CSRF configuration
        return GLOBAL_CSRF_PATTERN.matcher(fullContent).find();
    }
}