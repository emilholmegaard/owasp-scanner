package org.emilholmegaard.owaspscanner.scanners;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.emilholmegaard.owaspscanner.core.SecurityRule;
import org.emilholmegaard.owaspscanner.core.SecurityScanner;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.scanners.dotnet.AbstractDotNetSecurityRule;
import org.emilholmegaard.owaspscanner.scanners.dotnet.DotNetRuleFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Scanner implementation for .NET applications based on OWASP .NET Security Cheat Sheet.
 * Uses modular rule design and factory pattern for rule creation.
 */
public class DotNetScanner implements SecurityScanner {
    private final List<SecurityRule> rules;
    private final BaseScannerEngine scannerEngine;
    
    /**
     * Constructs a new DotNetScanner that initializes rules using the factory pattern.
     */
    public DotNetScanner() {
        // Use factory to get the rule implementations
        this.rules = DotNetRuleFactory.getInstance().createAllRules();
        this.scannerEngine = new BaseScannerEngine();
    }
    
    @Override
    public String getName() {
        return "OWASP .NET Security Scanner";
    }
    
    @Override
    public String getTechnology() {
        return "DotNet";
    }
    
    @Override
    public List<String> getSupportedFileExtensions() {
        return Arrays.asList("cs", "cshtml", "config", "csproj", "xml", "json");
    }
    
    @Override
    public List<SecurityViolation> scanFile(Path filePath) {
        List<SecurityViolation> violations = new ArrayList<>();
        
        try {
            // Use the scanner engine instance to read file content
            List<String> lines = scannerEngine.readFileWithFallback(filePath);
            
            // Skip empty files or files that couldn't be read
            if (lines.isEmpty()) {
                return violations;
            }
            
            // Quick check if any line in the file might match any rule pattern
            boolean fileNeedsDetailedCheck = false;
            for (SecurityRule rule : rules) {
                if (rule instanceof AbstractDotNetSecurityRule) {
                    AbstractDotNetSecurityRule dotNetRule = (AbstractDotNetSecurityRule) rule;
                    
                    for (String line : lines) {
                        if (dotNetRule.getPattern().matcher(line).find()) {
                            fileNeedsDetailedCheck = true;
                            break;
                        }
                    }
                    
                    if (fileNeedsDetailedCheck) {
                        break;
                    }
                } else {
                    // If any rule is not a DotNet rule, we need to do a detailed check
                    fileNeedsDetailedCheck = true;
                    break;
                }
            }
            
            // Skip detailed checking if no rule patterns matched
            if (!fileNeedsDetailedCheck) {
                return violations;
            }
            
            // Create a rule context for this file using the scanner engine
            RuleContext context = scannerEngine.new DefaultRuleContext(filePath, lines);
            
            // Process each line with each rule
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                int lineNumber = i + 1;
                
                for (SecurityRule rule : rules) {
                    if (rule.isViolatedBy(line, lineNumber, context)) {
                        violations.add(createViolation(rule, filePath, line, lineNumber));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error scanning file " + filePath + ": " + e.getMessage());
        }
        
        return violations;
    }
    
    /**
     * Creates a SecurityViolation object from the detected violation.
     */
    private SecurityViolation createViolation(SecurityRule rule, Path filePath, String line, int lineNumber) {
        return new SecurityViolation.Builder(
            rule.getId(),
            rule.getDescription(),
            filePath,
            lineNumber
        )
        .snippet(line.trim())
        .severity(rule.getSeverity())
        .remediation(rule.getRemediation())
        .reference(rule.getReference())
        .build();
    }
}
