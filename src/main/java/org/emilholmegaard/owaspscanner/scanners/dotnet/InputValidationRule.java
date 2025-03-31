package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Security rule implementation that checks for proper input validation in .NET
 * applications.
 * This rule analyzes source code to detect potential missing input validation
 * vulnerabilities.
 * It supports multiple validation approaches including:
 * <ul>
 * <li>Data Annotations</li>
 * <li>Model Validation</li>
 * <li>Fluent Validation</li>
 * <li>Custom Validation</li>
 * </ul>
 *
 * @since 1.0
 */
@Component
public class InputValidationRule extends AbstractDotNetSecurityRule {

    /**
     * Pattern to match common .NET Data Annotation validation attributes.
     * Includes Required, StringLength, Range, RegularExpression and other
     * validation attributes.
     */
    private static final Pattern DATA_ANNOTATIONS_PATTERN = Pattern
            .compile("(?i)\\[Required\\]|\\[StringLength\\]|\\[Range\\]|\\[RegularExpression\\]|" +
                    "\\[MinLength\\]|\\[MaxLength\\]|\\[EmailAddress\\]|\\[Url\\]|\\[Phone\\]|" +
                    "\\[CreditCard\\]|\\[Compare\\]|\\[DataType\\]");

    /**
     * Pattern to match model validation methods and properties in .NET.
     * Includes ModelState.IsValid, TryValidateModel and other validation related
     * patterns.
     */
    private static final Pattern MODEL_VALIDATION_PATTERN = Pattern
            .compile("(?i)ModelState\\.IsValid|TryValidateModel|ValidateAntiForgeryToken|" +
                    "\\.Validate\\(|Validator\\.|ValidationResult|IValidator");

    /**
     * Pattern to match FluentValidation framework usage.
     * Includes AbstractValidator, RuleFor and other FluentValidation specific
     * patterns.
     */
    private static final Pattern FLUENT_VALIDATION_PATTERN = Pattern
            .compile("(?i)AbstractValidator|RuleFor\\(|ValidatorFactory|IValidator");

    /**
     * Composite pattern that matches any type of validation approach.
     * Combines common validation patterns from all supported validation methods.
     */
    private static final Pattern ANY_VALIDATION_PATTERN = Pattern.compile(
            "(?i)\\[Required\\]|ModelState\\.IsValid|AbstractValidator|" +
                    "Regex\\.IsMatch|Sanitize|Validate|IsValid|CheckInput");

    /**
     * Constructs a new InputValidationRule with predefined security parameters.
     * Initializes the rule with a unique identifier, severity level, and detection
     * patterns.
     */
    public InputValidationRule() {
        super(
                "DOTNET-SEC-002",
                "Missing input validation",
                "HIGH",
                "Implement proper input validation using Data Annotations, FluentValidation, or custom validators. " +
                        "Apply whitelist validation and check ModelState.IsValid before processing user input.",
                "https://owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
                Pattern.compile("(?i)Request\\.|FromBody|\\[Bind|\\[FromQuery\\]|\\[FromRoute\\]|\\[FromForm\\]|" +
                        "HttpContext\\.Request|Model\\.|Form\\."));
    }

    /**
     * Checks if the given line of code violates the input validation rule.
     *
     * @param line       The line of code to check
     * @param lineNumber The line number in the source file
     * @param context    The rule context containing the full file content and
     *                   additional information
     * @return true if a violation is detected, false otherwise
     */
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Skip lines where input is not processed
        if (line.trim().startsWith("//") || line.trim().startsWith("/*") || line.trim().startsWith("*")) {
            return false;
        }

        // First, check if this line deals with input
        if (!super.getPattern().matcher(line).find()) {
            return false;
        }

        // Check file-level validation
        String fullFileContent = String.join("\n", context.getFileContent());
        if (hasGlobalValidation(fullFileContent)) {
            return false;
        }

        // Check surrounding context for validation
        String surroundingCode = context.getJoinedLinesAround(lineNumber, 10, "\n");
        return !ANY_VALIDATION_PATTERN.matcher(surroundingCode).find();
    }

    /**
     * Checks if the file contains any global validation configurations or patterns.
     * This includes middleware configurations, global filters, and class-level
     * validation attributes.
     *
     * @param fullFileContent The complete content of the source file
     * @return true if global validation is present, false otherwise
     */
    private boolean hasGlobalValidation(String fullFileContent) {
        return DATA_ANNOTATIONS_PATTERN.matcher(fullFileContent).find() ||
                MODEL_VALIDATION_PATTERN.matcher(fullFileContent).find() ||
                FLUENT_VALIDATION_PATTERN.matcher(fullFileContent).find() ||
                (fullFileContent.contains("services.AddControllers(") &&
                        fullFileContent.contains("ValidateModelStateAttribute"))
                ||
                (fullFileContent.contains("app.UseMiddleware<") &&
                        fullFileContent.contains("ValidationMiddleware"));
    }
}