package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.regex.Pattern;

/**
 * Rule to check for secure configuration in .NET applications.
 */
public class SecureConfigurationRule extends AbstractDotNetSecurityRule {
    
    private static final String RULE_ID = "DOTNET-SEC-006";
    private static final String DESCRIPTION = "Insecure configuration settings";
    private static final String SEVERITY = "MEDIUM";
    private static final String REMEDIATION = 
            "Use secure configuration storage like Azure Key Vault, Secret Manager, or environment variables. " +
            "Encrypt sensitive data and avoid storing secrets in config files.";
    private static final String REFERENCE = 
            "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#data-protection-configuration-net-462";
    
    private static final Pattern PATTERN = 
            Pattern.compile("(?i)<connectionStrings|<appSettings|\\\"ConnectionStrings\\\"|secrets\\.json|appsettings");
    
    // Patterns to identify potential secrets
    private static final Pattern SECRETS_PATTERN = Pattern.compile(
            "(?i)password|pwd|secret|key|token|apikey|connectionstring");
    
    // Patterns for secure storage/protection mechanisms
    private static final Pattern SECURE_STORAGE_PATTERN = Pattern.compile(
            "(?i)Azure\\.KeyVault|Microsoft\\.Extensions\\.Configuration\\.UserSecrets|" +
            "ProtectedData|" +
            "DPAPI|" +
            "Environment\\.GetEnvironmentVariable|" +
            "EnvironmentVariableTarget|" +
            "IConfiguration|" +
            "\\.AddEnvironmentVariables|" +
            "EncryptedData");
    
    /**
     * Creates a new SecureConfigurationRule.
     */
    public SecureConfigurationRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        String fileName = context.getFilePath().getFileName().toString().toLowerCase();
        
        // Focus on configuration files or configuration setup code
        if (isConfigurationFile(fileName) || isConfigurationSetupCode(line)) {
            // Check if this line contains sensitive information
            boolean containsSecrets = SECRETS_PATTERN.matcher(line).find();
            
            if (containsSecrets) {
                // Check for plaintext secrets
                boolean isPlainTextSecret = line.matches("(?i).*=.*\".*|.*:.*\".*") &&
                                          line.indexOf('"') != line.lastIndexOf('"');
                                          
                // Check if secure storage/protection is used in the file
                boolean usesSecureStorage = isUsingSecureStorage(context.getFileContent());
                
                // If we have plaintext secrets and no secure storage mechanism, flag as violation
                return isPlainTextSecret && !usesSecureStorage;
            }
        }
        
        return false;
    }
    
    /**
     * Determines if the file is a configuration file.
     */
    private boolean isConfigurationFile(String fileName) {
        return fileName.endsWith(".config") ||
               fileName.endsWith("appsettings.json") ||
               fileName.endsWith("web.config") ||
               fileName.endsWith("app.config") ||
               fileName.endsWith("secrets.json");
    }
    
    /**
     * Determines if the line contains configuration setup code.
     */
    private boolean isConfigurationSetupCode(String line) {
        return line.contains("ConfigureAppConfiguration") ||
               line.contains("IConfiguration") ||
               line.contains("ConfigurationBuilder") ||
               line.contains("appsettings.json") ||
               line.contains("ConnectionStrings");
    }
    
    /**
     * Checks if secure storage mechanisms are used in the file.
     */
    private boolean isUsingSecureStorage(java.util.List<String> fileContent) {
        String fullContent = String.join("\n", fileContent);
        
        // Check for secure storage mechanisms
        return SECURE_STORAGE_PATTERN.matcher(fullContent).find();
    }
}
