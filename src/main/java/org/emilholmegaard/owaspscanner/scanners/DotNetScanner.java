package org.emilholmegaard.owaspscanner.scanners;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.emilholmegaard.owaspscanner.core.SecurityRule;
import org.emilholmegaard.owaspscanner.core.SecurityScanner;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.scanners.dotnet.AbstractDotNetSecurityRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A security scanner implementation for .NET applications that analyzes source
 * code and configuration files
 * for potential security vulnerabilities based on the OWASP .NET Security Cheat
 * Sheet.
 * 
 * <p>
 * This scanner supports various .NET-related file types including C# source
 * files, Razor views,
 * configuration files, project files, and other XML/JSON based configuration
 * files.
 * </p>
 * 
 * <p>
 * The scanner uses a modular rule design pattern where individual security
 * rules can be
 * added or modified independently. It implements performance optimizations by
 * performing quick
 * pattern matching before detailed analysis.
 * </p>
 * 
 * <p>
 * Key features:
 * </p>
 * <ul>
 * <li>Configurable through dependency injection of rules and scanner
 * engine</li>
 * <li>Support for both .NET specific and generic security rules</li>
 * <li>Efficient file scanning with preliminary pattern matching</li>
 * <li>Detailed violation reporting with line numbers and context</li>
 * </ul>
 *
 * @author Emil Holmegaard
 * @version 1.0
 * @see SecurityScanner
 * @see AbstractDotNetSecurityRule
 * @see BaseScannerEngine
 */
@Component
public class DotNetScanner implements SecurityScanner {
    private final List<SecurityRule> rules;
    private final BaseScannerEngine scannerEngine;

    @Autowired
    public DotNetScanner(List<SecurityRule> dotNetRules, BaseScannerEngine scannerEngine) {
        this.rules = dotNetRules;
        this.scannerEngine = scannerEngine;
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
            // Use the injected scannerEngine for file reading
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

            // Create a rule context using the scannerEngine instance
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
                lineNumber)
                .snippet(line.trim())
                .severity(rule.getSeverity())
                .remediation(rule.getRemediation())
                .reference(rule.getReference())
                .build();
    }
}
