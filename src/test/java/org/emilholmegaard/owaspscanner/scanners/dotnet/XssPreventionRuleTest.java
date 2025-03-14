package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class XssPreventionRuleTest {

    private XssPreventionRule rule;
    
    @Mock
    private RuleContext context;
    
    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        rule = new XssPreventionRule();
        when(context.getFilePath()).thenReturn(Paths.get("HomeController.cs"));
    }
    
    @Test
    public void testVulnerableHtmlRaw() {
        // Setup
        String line = "@Html.Raw(Model.UserInput)";
        int lineNumber = 4;
        
        List<String> fileContent = Arrays.asList(
            "@model UserViewModel",
            "<div>",
            "    <h1>Welcome, @Model.Name</h1>",
            "    <div class=\"content\">",
            line,
            "    </div>",
            "</div>"
        );
        
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(eq(lineNumber), anyInt())).thenReturn(
            fileContent.subList(Math.max(0, lineNumber - 3), Math.min(fileContent.size(), fileNumber + 3))
        );
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertTrue(result, "Should detect XSS vulnerability in @Html.Raw()");
    }
    
    @Test
    public void testVulnerableResponseWrite() {
        // Setup
        String line = "Response.Write(userInput);";
        int lineNumber = 3;
        
        List<String> fileContent = Arrays.asList(
            "public ActionResult DisplayMessage(string userInput)",
            "{",
            "    // Dangerous - directly writing user input to response",
            line,
            "    return View();",
            "}"
        );
        
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(eq(lineNumber), anyInt())).thenReturn(
            fileContent.subList(0, fileContent.size())
        );
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertTrue(result, "Should detect XSS vulnerability in Response.Write()");
    }
    
    @Test
    public void testSafeEncoding() {
        // Setup
        String line = "var encodedOutput = HtmlEncoder.Encode(userInput);";
        int lineNumber = 3;
        
        List<String> fileContent = Arrays.asList(
            "public string SafeDisplay(string userInput)",
            "{",
            "    // Safely encoding user input",
            line,
            "    return $\"<div>{encodedOutput}</div>\";",
            "}"
        );
        
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(eq(lineNumber), anyInt())).thenReturn(
            fileContent.subList(0, fileContent.size())
        );
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not flag properly encoded content");
    }
    
    @Test
    public void testAutoEncodingWithRazor() {
        // Setup
        String line = "<div>@Model.Message</div>";
        int lineNumber = 2;
        
        List<String> fileContent = Arrays.asList(
            "@model MessageViewModel",
            "<h1>Message</h1>",
            line,
            "<p>Timestamp: @DateTime.Now</p>"
        );
        
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(eq(lineNumber), anyInt())).thenReturn(
            fileContent.subList(0, fileContent.size())
        );
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not flag auto-encoded Razor syntax");
    }
}
