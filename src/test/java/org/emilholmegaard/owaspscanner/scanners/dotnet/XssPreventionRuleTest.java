package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for XssPreventionRule using AAA pattern and parameterized tests.
 */
public class XssPreventionRuleTest extends AbstractRuleTest {

    private XssPreventionRule rule;
    
    @BeforeEach
    public void setUp() {
        super.baseSetUp();
        rule = new XssPreventionRule();
        when(context.getFilePath()).thenReturn(Paths.get("HomeController.cs"));
    }
    
    @ParameterizedTest
    @DisplayName("Should detect XSS in vulnerable code")
    @CsvSource({
        // Line number (0-based), Code containing XSS vulnerability
        "4, @Html.Raw(Model.UserInput)",
        "3, Response.Write(userInput);",
        "5, document.write(\"<script>\" + data + \"</script>\");",
        "3, element.innerHtml = userContent;",
        "4, return Content(\"<div>\" + message + \"</div>\", \"text/html\");"
    })
    void shouldDetectXssVulnerability(int lineNumber, String vulnerableLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "@model UserViewModel",
            "<div>",
            "    <h1>Welcome, @Model.Name</h1>",
            "    <div class=\"content\">",
            "        @Html.Raw(Model.UserInput)",
            "    </div>",
            "</div>"
        );
        String line = setupTestContext(fileContent, lineNumber, vulnerableLine);
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertTrue(result, "Should detect XSS vulnerability in: " + vulnerableLine);
    }
    
    @ParameterizedTest
    @DisplayName("Should not detect XSS in secure code")
    @CsvSource({
        // Line number (0-based), Secure code without XSS
        "4, @Html.Encode(Model.UserInput)",
        "3, var encodedOutput = HtmlEncoder.Encode(userInput);",
        "3, ViewBag.Output = HttpUtility.HtmlEncode(message);",
        "4, <div>@Model.SafeContent</div>",
        // Additional case converted from individual test
        "2, <div>@Model.Message</div>"
    })
    void shouldNotDetectXssInSecureCode(int lineNumber, String secureLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "@model UserViewModel",
            "<div>",
            "    <h1>Welcome, @Model.Name</h1>",
            "    <div class=\"content\">",
            "        @Html.Encode(Model.UserInput)",
            "    </div>",
            "</div>"
        );
        String line = setupTestContext(fileContent, lineNumber, secureLine);
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertFalse(result, "Should not detect XSS vulnerability in: " + secureLine);
    }
    
    @ParameterizedTest
    @DisplayName("Should detect XSS vulnerabilities in JavaScript")
    @CsvSource({
        "3, var userScript = \"<script>\" + userInput + \"</script>\";"
    })
    void shouldDetectXssInJavaScript(int lineNumber, String vulnerableLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "@model UserViewModel",
            "<script>",
            "    // Dangerous - direct insertion of user input into JavaScript",
            "    var userScript = \"<script>\" + userInput + \"</script>\";",
            "    $(\"#result\").html(userScript);",
            "</script>"
        );
        
        // Important: We need to explicitly indicate this is a JavaScript file
        when(context.getFilePath()).thenReturn(Paths.get("JavaScriptFile.js"));
        
        // Get the line indices to simulate the correct context
        int scriptBlockStart = 1; // The index of the "<script>" line
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Setup the context with the right surrounding lines
        String line = setupTestContext(fileContent, lineNumber, vulnerableLine);
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertTrue(result, "Should detect XSS in JavaScript: " + vulnerableLine);
    }
    
    @ParameterizedTest
    @DisplayName("Should detect XSS vulnerabilities in Content methods")
    @CsvSource({
        "5, return Content(\"<h1>\" + title + \"</h1><div>\" + body + \"</div>\", \"text/html\");"
    })
    void shouldDetectXssInContentMethod(int lineNumber, String vulnerableLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "public class ContentController : Controller {",
            "    public ActionResult ShowContent(string title, string body) {",
            "        // No encoding or validation",
            "        // Vulnerable to XSS",
            "        return Content(\"<h1>\" + title + \"</h1><div>\" + body + \"</div>\", \"text/html\");",
            "    }",
            "}"
        );
        String line = setupTestContext(fileContent, lineNumber, vulnerableLine, Paths.get("ContentController.cs"));
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertTrue(result, "Should detect XSS in Content method: " + vulnerableLine);
    }
    
    @ParameterizedTest
    @DisplayName("Should not flag auto-encoded Razor syntax")
    @CsvSource({
        "2, <div>@Model.Message</div>"
    })
    void shouldNotFlagAutoEncodedRazorSyntax(int lineNumber, String secureLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "@model MessageViewModel",
            "<h1>Message</h1>",
            "<div>@Model.Message</div>",
            "<p>Timestamp: @DateTime.Now</p>"
        );
        String line = setupTestContext(fileContent, lineNumber, secureLine, Paths.get("MessageView.cshtml"));
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertFalse(result, "Should not flag auto-encoded Razor syntax: " + secureLine);
    }
}