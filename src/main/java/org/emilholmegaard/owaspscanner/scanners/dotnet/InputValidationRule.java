package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Rule to check for proper input validation in .NET applications.
 * Reduces false positives by considering various validation approaches.
 */
public class InputValidationRule extends AbstractDotNetSecurityRule {
    
    private static final String RULE_ID = "DOTNET-SEC-002";
    private static final String DESCRIPTION = "Insufficient Input Validation";
    private static final String SEVERITY = "CRITICAL";
    private static final String REMEDIATION = 
            "Implement proper input validation using Data Annotations, FluentValidation, or custom validators. " +
            "Apply whitelist validation and check ModelState.IsValid before processing user input.";
    private static final String REFERENCE = 
            "https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#validation";
    
    // Pattern for identifying input sources (expanded to cover more cases)
    private static final Pattern PATTERN = 
            Pattern.compile("(?i)Request\\.|FromBody|\\[Bind|\\[FromQuery\\]|\\[FromRoute\\]|\\[FromForm\\]|" +
                           "HttpContext\\.Request|controller\\.Request|this\\.Request|Query\\[|Form\\[|IFormFile");
    
    // Patterns for different validation approaches
    private static final Pattern DATA_ANNOTATIONS_PATTERN = 
            Pattern.compile("(?i)\\[Required\\]|\\[StringLength\\]|\\[Range\\]|\\[RegularExpression\\]|" +
                           "\\[MinLength\\]|\\[MaxLength\\]|\\[EmailAddress\\]|\\[Url\\]|\\[Phone\\]|" +
                           "\\[CreditCard\\]|\\[Compare\\]|\\[DataType\\]");
    
    private static final Pattern MODEL_VALIDATION_PATTERN =
            Pattern.compile("(?i)ModelState\\.IsValid|TryValidateModel|ValidateAntiForgeryToken|" +
                           "\\.Validate\\(|Validator\\.|ValidationResult|IValidator");
    
    private static final Pattern FLUENT_VALIDATION_PATTERN = 
            Pattern.compile("(?i)AbstractValidator|RuleFor\\(|ValidatorFactory|IValidator");
    
    private static final Pattern REGEX_VALIDATION_PATTERN =
            Pattern.compile("(?i)Regex\\.IsMatch|new Regex|Match\\.|Matches\\.|System\\.Text\\.RegularExpressions");
    
    private static final Pattern CUSTOM_VALIDATION_PATTERN =
            Pattern.compile("(?i)Sanitize|Validate|IsValid|CheckInput|Whitelist|Filter");
    
    /**
     * Creates a new InputValidationRule.
     */
    public InputValidationRule() {
        super(RULE_ID, DESCRIPTION, SEVERITY, REMEDIATION, REFERENCE, PATTERN);
    }
    
    @Override
    protected boolean checkViolation(String line, int lineNumber, RuleContext context) {
        // Skip lines where input is not processed (e.g., in comments, string literals)
        if (line.trim().startsWith("//") || line.trim().startsWith("/*") || line.trim().startsWith("*")) {
            return false;
        }
        
        // First, check if this line deals with input
        if (!processesInput(line)) {
            return false;
        }
        
        // Check if the class/file already has validation attributes on properties
        boolean hasDataAnnotations = hasDataAnnotationsInFile(context.getFileContent());
        
        // Check if ModelState.IsValid is used appropriately in action methods
        boolean hasModelValidation = hasModelValidationInFile(context.getFileContent());
        
        // Check for FluentValidation usage
        boolean hasFluentValidation = hasFluentValidationInFile(context.getFileContent());
        
        // If any proper validation approach is detected at the file level, reduce false positives
        if (hasGlobalValidation(context.getFileContent()) && (hasDataAnnotations || hasModelValidation || hasFluentValidation)) {
            return false;
        }
        
        // Look for validation in surrounding lines (for contexts where validation isn't at the class level)
        List<String> surroundingLines = context.getLinesAround(lineNumber, 10);
        String surroundingCode = String.join("\n", surroundingLines);
        
        boolean hasSurroundingValidation = hasValidationInCode(surroundingCode);
        
        // Return true only if we have user input with no validation
        return !hasSurroundingValidation;
    }
    
    /**
     * Determines if a line processes user input.
     */
    private boolean processesInput(String line) {
        return PATTERN.matcher(line).find();
    }
    
    /**
     * Checks if the file uses Data Annotations for validation.
     */
    private boolean hasDataAnnotationsInFile(List<String> fileContent) {
        return fileContent.stream().anyMatch(line -> DATA_ANNOTATIONS_PATTERN.matcher(line).find());
    }
    
    /**
     * Checks if the file uses ModelState validation.
     */
    private boolean hasModelValidationInFile(List<String> fileContent) {
        return fileContent.stream().anyMatch(line -> MODEL_VALIDATION_PATTERN.matcher(line).find());
    }
    
    /**
     * Checks if the file uses FluentValidation.
     */
    private boolean hasFluentValidationInFile(List<String> fileContent) {
        return fileContent.stream().anyMatch(line -> FLUENT_VALIDATION_PATTERN.matcher(line).find());
    }
    
    /**
     * Checks if validation is present in a code snippet.
     */
    private boolean hasValidationInCode(String code) {
        return DATA_ANNOTATIONS_PATTERN.matcher(code).find() ||
               MODEL_VALIDATION_PATTERN.matcher(code).find() ||
               FLUENT_VALIDATION_PATTERN.matcher(code).find() ||
               REGEX_VALIDATION_PATTERN.matcher(code).find() ||
               CUSTOM_VALIDATION_PATTERN.matcher(code).find();
    }
    
    /**
     * Checks if the application has global validation filters or attributes.
     */
    private boolean hasGlobalValidation(List<String> fileContent) {
        String fullContent = String.join("\n", fileContent);
        
        // Look for global validation setup in ASP.NET Core
        boolean hasValidationFilter = fullContent.contains("services.AddControllers(") &&
                                    fullContent.contains("ValidateModelStateAttribute") ||
                                    fullContent.contains("options.Filters.Add") &&
                                    fullContent.contains("ValidateModel");
                                    
        // Look for API input validation middleware
        boolean hasValidationMiddleware = fullContent.contains("app.UseMiddleware<") &&
                                        (fullContent.contains("ValidationMiddleware") ||
                                         fullContent.contains("RequestValidator"));
                                         
        return hasValidationFilter || hasValidationMiddleware;
    }
}
