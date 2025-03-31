package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Rule to check for secure authentication practices in .NET applications.
 */
@Component
public class AuthenticationRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-007";
    private static final String DESCRIPTION = "Insecure authentication practices";
    private static final String SEVERITY = "HIGH";
    private static final String REMEDIATION = "Use ASP.NET Core Identity with strong password policies. Implement secure password "
            +
            "storage with modern hashing algorithms like PBKDF2, Argon2, or BCrypt.";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#authentication";

    private static final Pattern PATTERN = Pattern
            .compile("(?i)password|authenticate|login|signin|hash|identity|user manager|usermanager");

    // Secure password storage patterns
    private static final Pattern SECURE_HASH_PATTERN = Pattern.compile(
            "(?i)PasswordHasher|PBKDF2|Rfc2898DeriveBytes|Argon2|BCrypt|" +
                    "HashPassword|passwordHasher|" +
                    "Microsoft\\.AspNetCore\\.Identity");

    // Weak hashing patterns
    private static final Pattern WEAK_HASH_PATTERN = Pattern.compile(
            "(?i)MD5|SHA1|new SHA1|GetBytes\\(|Convert\\.ToBase64String|" +
                    "System\\.Security\\.Cryptography\\.SHA1");

    // Password policy patterns
    private static final Pattern PASSWORD_POLICY_PATTERN = Pattern.compile(
            "(?i)RequiredLength|RequireDigit|RequireUppercase|RequireLowercase|" +
                    "RequireNonAlphanumeric|PasswordOptions|RequiredUniqueChars|" +
                    "PasswordValidator|PasswordSignInAsync");

    /**
     * Creates a new AuthenticationRule.
     */
    public AuthenticationRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }

    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if this line deals with authentication or passwords
        if (!isAuthenticationRelated(line)) {
            return false;
        }

        // Get file content for analysis
        String fileContent = String.join("\n", context.getFileContent());

        // Check for usage of secure hashing algorithms at file level
        boolean hasSecureHashing = SECURE_HASH_PATTERN.matcher(fileContent).find();

        // Check for password policy configuration
        boolean hasPasswordPolicy = PASSWORD_POLICY_PATTERN.matcher(fileContent).find();

        // Check for weak/insecure hashing
        boolean hasWeakHashing = WEAK_HASH_PATTERN.matcher(fileContent).find();

        // Check if using ASP.NET Identity
        boolean usesAspNetIdentity = fileContent.contains("Microsoft.AspNetCore.Identity") ||
                fileContent.contains("AddIdentity") ||
                fileContent.contains("UserManager<") ||
                fileContent.contains("SignInManager<");

        // Custom authentication implementations should be flagged unless they use
        // secure practices
        if (!usesAspNetIdentity) {
            // If implementing custom auth, must have secure hashing and password policies
            return !hasSecureHashing || hasWeakHashing || !hasPasswordPolicy;
        } else {
            // If using ASP.NET Identity, just check for weak hashing overrides
            return hasWeakHashing;
        }
    }

    /**
     * Determines if a line is related to authentication functionality.
     */
    private boolean isAuthenticationRelated(String line) {
        return line.matches("(?i).*password.*hash.*|.*createuser.*|.*register.*|.*authenticate.*|.*identity.*|" +
                ".*login.*|.*signin.*|.*usermanager.*|.*signinmanager.*|.*generatepassword.*|" +
                ".*passwordhasher.*|.*createasync.*\\(.*user.*\\)|.*addpassword.*");
    }
}
