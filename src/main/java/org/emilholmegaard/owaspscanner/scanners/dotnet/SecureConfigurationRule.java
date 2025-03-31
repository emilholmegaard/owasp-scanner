package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Rule to check for secure configuration in .NET applications.
 */
@Component
public class SecureConfigurationRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-006";
    private static final String DESCRIPTION = "Insecure configuration settings";
    private static final String SEVERITY = "MEDIUM";
    private static final String REMEDIATION = "Use secure configuration storage like Azure Key Vault, Secret Manager, or environment variables. "
            +
            "Encrypt sensitive data and avoid storing secrets in config files.";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#data-protection-configuration-net-462";

    // Optimized initial pattern for first-pass scanning
    private static final Pattern PATTERN = Pattern
            .compile("(?i)(?:config|json|password|secret|key|token|apikey|connectionstring)");

    // Focused pattern for config file detection
    private static final Pattern CONFIG_FILE_PATTERN = Pattern
            .compile("(?i)(?:\\.config|\\.json|web\\.config|app\\.config|secrets\\.json|appsettings)$");

    // Pattern to identify potential secrets with bounded repetition for better
    // performance
    private static final Pattern SECRETS_PATTERN = Pattern.compile(
            "(?i)(?:password|pwd|secret|key|token|apikey|connectionstring)[\\s=\":\\[]{1,5}([^\\s=\"\\[]+)");

    // Simplified secure storage pattern
    private static final Pattern SECURE_STORAGE_PATTERN = Pattern.compile(
            "(?i)(?:Azure\\.KeyVault|UserSecrets|ProtectedData|DPAPI|GetEnvironmentVariable|" +
                    "EnvironmentVariableTarget|IConfiguration|AddEnvironmentVariables|EncryptedData)");

    /**
     * Creates a new SecureConfigurationRule.
     */
    public SecureConfigurationRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }

    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        String fileName = context.getFilePath().getFileName().toString().toLowerCase();

        // First check: Is this a configuration file at all? If not, return quickly
        if (!isConfigurationFile(fileName)) {
            return false;
        }

        // Second check: Does the line actually contain sensitive data?
        if (SECRETS_PATTERN.matcher(line).find()) {
            // Check if using secure storage mechanism
            if (line.contains("${") || SECURE_STORAGE_PATTERN.matcher(line).find()) {
                return false; // Using secure reference or protected data
            }
            return true; // Found unprotected secrets
        }

        return false;
    }

    /**
     * Determines if the file is a configuration file.
     */
    private boolean isConfigurationFile(String fileName) {
        return CONFIG_FILE_PATTERN.matcher(fileName).find();
    }
}
