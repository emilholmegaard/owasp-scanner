package org.emilholmegaard.owaspscanner.core;

/**
 * A rule that can be checked against code to find security violations.
 */
public interface SecurityRule {
    /**
     * Returns the unique identifier of this rule.
     */
    String getId();
    
    /**
     * Returns a human-readable description of this rule.
     */
    String getDescription();
    
    /**
     * Returns the severity level of violations of this rule.
     */
    String getSeverity();
    
    /**
     * Returns guidance on how to fix violations of this rule.
     */
    String getRemediation();
    
    /**
     * Returns a link to more information about this rule.
     */
    String getReference();
    
    /**
     * Checks a line of code for violations of this rule.
     *
     * @param line The line of code to check
     * @param lineNumber The line number in the file
     * @param context Additional context that might be needed for the check
     * @return true if the line violates this rule, false otherwise
     */
    boolean isViolatedBy(String line, int lineNumber, RuleContext context);
}