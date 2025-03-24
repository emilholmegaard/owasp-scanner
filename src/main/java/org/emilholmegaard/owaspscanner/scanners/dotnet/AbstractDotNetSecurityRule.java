package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.emilholmegaard.owaspscanner.core.SecurityRule;

import java.util.regex.Pattern;

/**
 * Base abstract class for all DotNet security rules.
 * Provides common functionality for rule implementation.
 */
public abstract class AbstractDotNetSecurityRule implements SecurityRule {
    private final String id;
    private final String description;
    private final String severity;
    private final String remediation;
    private final String reference;
    private final Pattern pattern;
    
    /**
     * Creates a new DotNet security rule.
     *
     * @param id Unique identifier for the rule (e.g., "DOTNET-SEC-001")
     * @param description Human-readable description of what the rule checks for
     * @param severity The severity level of violations (e.g., "HIGH", "MEDIUM", "LOW")
     * @param remediation Guidance on how to fix violations
     * @param reference Link to more information about this rule
     * @param pattern Regex pattern for quick initial check
     */
    public AbstractDotNetSecurityRule(
            String id,
            String description,
            String severity,
            String remediation,
            String reference,
            Pattern pattern) {
        this.id = id;
        this.description = description;
        this.severity = severity;
        this.remediation = remediation;
        this.reference = reference;
        this.pattern = pattern;
    }
    
    @Override
    public String getId() {
        return id;
    }
    
    @Override
    public String getDescription() {
        return description;
    }
    
    @Override
    public String getSeverity() {
        return severity;
    }
    
    @Override
    public String getRemediation() {
        return remediation;
    }
    
    @Override
    public String getReference() {
        return reference;
    }
    
    /**
     * Gets the regex pattern used for quick checks of rule violations.
     * 
     * @return The Pattern object used for quick violation detection
     */
    public Pattern getPattern() {
        return pattern;
    }
    
    @Override
    public boolean isViolatedBy(String line, int lineNumber, RuleContext context) {
        // First quick check using regex for improved performance
        if (pattern.matcher(line).find()) {
            // If potential match, use the more detailed check
            return checkViolation(line, lineNumber, context);
        }
        return false;
    }
    
    /**
     * Performs detailed check for rule violations.
     * Subclasses must implement this method with their specific logic.
     *
     * @param line The line to check
     * @param lineNumber The line number in the file
     * @param context Additional context needed for the check
     * @return true if the line violates this rule, false otherwise
     */
    protected abstract boolean checkViolation(String line, int lineNumber, RuleContext context);
}
