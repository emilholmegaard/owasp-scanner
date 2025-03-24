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
    
    // Combined pattern for any validation
    private static final Pattern ANY_VALIDATION_PATTERN = Pattern.compile(
            "(?i)\\[Required\\]|\\[StringLength\\]|\\[Range\\]|\\[RegularExpression\\]|" +
            "\\[MinLength\\]|\\[MaxLength\\]|\\[EmailAddress\\]|\\[Url\\]|\\[Phone\\]|" +
            "\\[CreditCard\\]|\\[Compare\\]|\\[DataType\\]|" +
            "ModelState\\.IsValid|TryValidateModel|ValidateAntiForgeryToken|" +
            "\\.Validate\\(|Validator\\.|ValidationResult|IValidator|" +
            "AbstractValidator|RuleFor\\(|ValidatorFactory|" +
            "Regex\\.IsMatch|new Regex|Match\\.|Matches\\.|System\\.Text\\.RegularExpressions|" +
            "Sanitize|Validate|IsValid|CheckInput|Whitelist|Filter");
    
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
        
        // Use efficient cached file content check for global validation patterns
        String fullFileContent = String.join("\n", context.getFileContent());
        
        // Check if the class/file already has validation attributes on properties
        boolean hasDataAnnotations = DATA_ANNOTATIONS_PATTERN.matcher(fullFileContent).find();
        
        // Check if ModelState.IsValid is used appropriately in action methods
        boolean hasModelValidation = MODEL_VALIDATION_PATTERN.matcher(fullFileContent).find();
        
        // Check for FluentValidation usage
        boolean hasFluentValidation = FLUENT_VALIDATION_PATTERN.matcher(fullFileContent).find();
        
        // If any proper validation approach is detected at the file level, reduce false positives
        if (hasGlobalValidation(fullFileContent) && (hasDataAnnotations || hasModelValidation || hasFluentValidation)) {
            return false;
        }
        
        // Look for validation in surrounding lines using cached context
        String surroundingCode = context.getJoinedLinesAround(lineNumber, 10, "\n");
        
        // Use combined pattern match for better performance
        boolean hasSurroundingValidation = ANY_VALIDATION_PATTERN.matcher(surroundingCode).find();
        
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
     * Checks if the application has global validation filters or attributes.
     * 
     * @param fullFileContent The full file content as a joined string
     * @return True if global validation is configured
     */
    private boolean hasGlobalValidation(String fullFileContent) {
        // Look for global validation setup in ASP.NET Core
        boolean hasValidationFilter = fullFileContent.contains("services.AddControllers(") &&
                                    fullFileContent.contains("ValidateModelStateAttribute") ||
                                    fullFileContent.contains("options.Filters.Add") &&
                                    fullFileContent.contains("ValidateModel");
                                    
        // Look for API input validation middleware
        boolean hasValidationMiddleware = fullFileContent.contains("app.UseMiddleware<") &&
                                        (fullFileContent.contains("ValidationMiddleware") ||
                                         fullFileContent.contains("RequestValidator"));
                                         
        return hasValidationFilter || hasValidationMiddleware;
    }
}