package org.emilholmegaard.owaspscanner.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Represents a security violation found by a scanner.
 */
public class SecurityViolation {
    private String ruleId;
    private String description;
    private transient Path filePath; // Mark as transient to avoid serialization issues
    private String filePathString; // Add string representation for serialization
    private int lineNumber;
    private String snippet;
    private String severity;
    private String remediation;
    private String reference;

    // Constructors, getters, setters

    public SecurityViolation(String ruleId, String description, Path filePath, int lineNumber, 
                           String snippet, String severity, String remediation, String reference) {
        this.ruleId = ruleId;
        this.description = description;
        this.filePath = filePath;
        this.filePathString = filePath != null ? filePath.toString() : null;
        this.lineNumber = lineNumber;
        this.snippet = snippet;
        this.severity = severity;
        this.remediation = remediation;
        this.reference = reference;
    }

    // Getters
    public String getRuleId() { return ruleId; }
    public String getDescription() { return description; }
    public Path getFilePath() { return filePath; }
    public String getFilePathString() { return filePathString; }
    public int getLineNumber() { return lineNumber; }
    public String getSnippet() { return snippet; }
    public String getSeverity() { return severity; }
    public String getRemediation() { return remediation; }
    public String getReference() { return reference; }

    // Builder pattern for easier construction
    public static class Builder {
        private String ruleId;
        private String description;
        private Path filePath;
        private int lineNumber;
        private String snippet;
        private String severity = "MEDIUM"; // Default value
        private String remediation = "";
        private String reference = "";

        public Builder(String ruleId, String description, Path filePath, int lineNumber) {
            this.ruleId = ruleId;
            this.description = description;
            this.filePath = filePath;
            this.lineNumber = lineNumber;
        }

        public Builder snippet(String snippet) {
            this.snippet = snippet;
            return this;
        }

        public Builder severity(String severity) {
            this.severity = severity;
            return this;
        }

        public Builder remediation(String remediation) {
            this.remediation = remediation;
            return this;
        }

        public Builder reference(String reference) {
            this.reference = reference;
            return this;
        }

        public SecurityViolation build() {
            return new SecurityViolation(ruleId, description, filePath, lineNumber, 
                                       snippet, severity, remediation, reference);
        }
    }
}