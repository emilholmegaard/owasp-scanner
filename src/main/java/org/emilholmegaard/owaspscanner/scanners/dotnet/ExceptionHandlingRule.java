package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Rule to check for proper exception handling in .NET applications.
 */
@Component
public class ExceptionHandlingRule extends AbstractDotNetSecurityRule {

    private static final String RULE_ID = "DOTNET-SEC-009";
    private static final String DESCRIPTION = "Insecure exception handling";
    private static final String SEVERITY = "MEDIUM";
    private static final String REMEDIATION = "Implement proper exception handling that doesn't expose sensitive information. "
            +
            "Use custom error pages and global exception handlers instead of exposing exception details.";
    private static final String REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#exception-handling";

    private static final Pattern PATTERN = Pattern
            .compile("(?i)try|catch|exception|throw|IExceptionHandler|UseExceptionHandler");

    // Patterns for exposing exception details
    private static final Pattern EXPOSE_DETAILS_PATTERN = Pattern.compile(
            "(?i)Response\\.Write\\(.*ex|return ex|" +
                    "\\.Message|" +
                    "ToString\\(\\)|" +
                    "InnerException|" +
                    "StackTrace");

    // Patterns for safe exception handling
    private static final Pattern SAFE_HANDLING_PATTERN = Pattern.compile(
            "(?i)UseExceptionHandler|" +
                    "IExceptionHandler|" +
                    "app\\.UseStatusCodePages|" +
                    "CustomErrors|" +
                    "UseMiddleware<ExceptionMiddleware>|" +
                    "ILogger|" +
                    "_logger");

    /**
     * Creates a new ExceptionHandlingRule.
     */
    public ExceptionHandlingRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }

    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Check if the application uses global exception handling
        if (hasGlobalExceptionHandling(context.getFileContent())) {
            return false;
        }

        // Check if this is a catch block
        if (line.matches("(?i).*catch.*\\(.*Exception.*\\).*")) {
            // Look for code that exposes exception details within the catch block
            List<String> linesAfter = getLinesInCatchBlock(lineNumber, context);

            // Check if exception details are exposed to client
            return linesAfter.stream()
                    .anyMatch(l -> EXPOSE_DETAILS_PATTERN.matcher(l).find());
        }

        return false;
    }

    /**
     * Gets the lines inside a catch block.
     */
    private List<String> getLinesInCatchBlock(int lineNumber, RuleContext context) {
        int endLine = lineNumber + 10; // Look at most 10 lines ahead
        int bracketCount = 0;
        boolean foundOpeningBracket = false;

        for (int i = lineNumber; i < Math.min(lineNumber + 10, context.getFileContent().size()); i++) {
            String line = context.getFileContent().get(i);

            if (!foundOpeningBracket && line.contains("{")) {
                foundOpeningBracket = true;
                bracketCount = 1;
                continue;
            }

            if (foundOpeningBracket) {
                for (char c : line.toCharArray()) {
                    if (c == '{')
                        bracketCount++;
                    if (c == '}')
                        bracketCount--;
                }

                // If brackets are balanced, we've found the end of the catch block
                if (bracketCount == 0) {
                    endLine = i;
                    break;
                }
            }
        }

        // Return the lines in the catch block
        return context.getFileContent().subList(
                lineNumber,
                Math.min(endLine + 1, context.getFileContent().size()));
    }

    /**
     * Checks if the application uses global exception handling.
     */
    private boolean hasGlobalExceptionHandling(List<String> fileContent) {
        String fullContent = String.join("\n", fileContent);

        // Common patterns for global exception handling in ASP.NET Core
        return fullContent.contains("app.UseExceptionHandler") ||
                fullContent.contains("AddExceptionHandler") ||
                fullContent.contains("UseMiddleware<ExceptionMiddleware>") ||
                fullContent.contains("app.UseStatusCodePages") ||
                fullContent.contains("<customErrors mode=") ||
                SAFE_HANDLING_PATTERN.matcher(fullContent).find();
    }
}
