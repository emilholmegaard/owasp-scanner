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
        "4, return Content(\"<div>\" + message + \"</div>\", \"text/html\");",
        // Additional cases converted from individual tests
        "5, return Content(\"<h1>\" + title + \"</h1><div>\" + body + \"</div>\", \"text/html\");",
        "3, var userScript = \"<script>\" + userInput + \"</script>\";"
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
    @DisplayName("Should properly analyze content in different file types")
    @CsvSource({
        // filename, line number, content, expected result (true=violation, false=secure)
        "ContentController.cs, 5, return Content(\"<h1>\" + title + \"</h1><div>\" + body + \"</div>\", \"text/html\");, true",
        "MessageView.cshtml, 2, <div>@Model.Message</div>, false", 
        "JavaScriptFile.js, 3, var userScript = \"<script>\" + userInput + \"</script>\";, true"
    })
    void shouldAnalyzeContentInDifferentFileTypes(String filename, int lineNumber, String content, boolean expectedViolation) {
        // Arrange
        List<String> fileContent;
        if (filename.endsWith(".cshtml")) {
            fileContent = codeLines(
                "@model MessageViewModel",
                "<h1>Message</h1>",
                "<div>@Model.Message</div>",
                "<p>Timestamp: @DateTime.Now</p>"
            );
        } else if (filename.endsWith(".js")) {
            fileContent = codeLines(
                "@model UserViewModel",
                "<script>",
                "    // Dangerous - direct insertion of user input into JavaScript",
                "    var userScript = \"<script>\" + userInput + \"</script>\";",
                "    $(\"#result\").html(userScript);",
                "</script>"
            );
        } else {
            fileContent = codeLines(
                "public class ContentController : Controller {",
                "    public ActionResult ShowContent(string title, string body) {",
                "        // No encoding or validation",
                "        // Vulnerable to XSS",
                "        return Content(\"<h1>\" + title + \"</h1><div>\" + body + \"</div>\", \"text/html\");",
                "    }",
                "}"
            );
        }
        
        setupTestContext(fileContent, lineNumber, content, Paths.get(filename));
        
        // Act
        boolean result = rule.isViolatedBy(content, lineNumber, context);
        
        // Assert
        if (expectedViolation) {
            assertTrue(result, "Should detect XSS vulnerability in: " + content);
        } else {
            assertFalse(result, "Should not detect XSS vulnerability in: " + content);
        }
    }
}