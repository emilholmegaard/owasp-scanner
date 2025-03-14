package org.emilholmegaard.owaspscanner.scanners;

import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DotNetScannerTest {
    
    private DotNetScanner scanner;
    
    @BeforeEach
    void setUp() {
        scanner = new DotNetScanner();
    }
    
    @Test
    void testGetName() {
        assertEquals("OWASP .NET Security Scanner", scanner.getName());
    }
    
    @Test
    void testGetTechnology() {
        assertEquals("DotNet", scanner.getTechnology());
    }
    
    @Test
    void testGetSupportedFileExtensions() {
        List<String> extensions = scanner.getSupportedFileExtensions();
        assertTrue(extensions.contains("cs"));
        assertTrue(extensions.contains("cshtml"));
        assertTrue(extensions.contains("config"));
    }
    
    @Test
    void testCanProcessFile() {
        assertTrue(scanner.canProcessFile(Path.of("Test.cs")));
        assertTrue(scanner.canProcessFile(Path.of("View.cshtml")));
        assertTrue(scanner.canProcessFile(Path.of("web.config")));
        assertFalse(scanner.canProcessFile(Path.of("script.js")));
        assertFalse(scanner.canProcessFile(Path.of("style.css")));
    }
    
    @Test
    void testScanFileWithSqlInjectionVulnerability(@TempDir Path tempDir) throws IOException {
        // Create a temporary file with a SQL injection vulnerability
        Path testFile = tempDir.resolve("TestController.cs");
        String vulnerableCode = 
            "public class TestController {\n" +
            "    public IActionResult GetUser(string id) {\n" +
            "        string query = \"SELECT * FROM Users WHERE Id = \" + id;\n" +
            "        SqlCommand command = new SqlCommand(query, connection);\n" +
            "        var reader = command.ExecuteReader();\n" +
            "        return Ok(reader);\n" +
            "    }\n" +
            "}";
        Files.writeString(testFile, vulnerableCode);
        
        // Scan the file
        List<SecurityViolation> violations = scanner.scanFile(testFile);
        
        // Verify violations
        assertTrue(!violations.isEmpty(), "Should find at least one violation");
        boolean foundSqlInjection = violations.stream()
            .anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-003") && 
                   v.getDescription().contains("SQL Injection"));
        
        assertTrue(foundSqlInjection, "Should detect SQL injection vulnerability");
    }
    
    @Test
    void testScanFileWithXssVulnerability(@TempDir Path tempDir) throws IOException {
        // Create a temporary file with a XSS vulnerability
        Path testFile = tempDir.resolve("UserView.cshtml");
        String vulnerableCode = 
            "@model UserModel\n" +
            "<div>\n" +
            "    <h1>User Profile</h1>\n" +
            "    <div>@Html.Raw(Model.UserComments)</div>\n" +
            "</div>";
        Files.writeString(testFile, vulnerableCode);
        
        // Scan the file
        List<SecurityViolation> violations = scanner.scanFile(testFile);
        
        // Verify violations
        assertTrue(!violations.isEmpty(), "Should find at least one violation");
        boolean foundXss = violations.stream()
            .anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-004") && 
                   v.getDescription().contains("Cross-Site Scripting"));
        
        assertTrue(foundXss, "Should detect XSS vulnerability");
    }
    
    @Test
    void testScanFileWithNoViolations(@TempDir Path tempDir) throws IOException {
        // Create a temporary file with no vulnerabilities
        Path testFile = tempDir.resolve("SecureController.cs");
        String secureCode = 
            "public class SecureController {\n" +
            "    [HttpPost]\n" +
            "    [ValidateAntiForgeryToken]\n" +
            "    public IActionResult CreateUser([Bind(\"Name,Email\")] UserModel model) {\n" +
            "        if (ModelState.IsValid) {\n" +
            "            string query = \"INSERT INTO Users (Name, Email) VALUES (@Name, @Email)\";\n" +
            "            SqlCommand command = new SqlCommand(query, connection);\n" +
            "            command.Parameters.AddWithValue(\"@Name\", model.Name);\n" +
            "            command.Parameters.AddWithValue(\"@Email\", model.Email);\n" +
            "            command.ExecuteNonQuery();\n" +
            "            return RedirectToAction(\"Index\");\n" +
            "        }\n" +
            "        return View(model);\n" +
            "    }\n" +
            "}";
        Files.writeString(testFile, secureCode);
        
        // Scan the file
        List<SecurityViolation> violations = scanner.scanFile(testFile);
        
        // Verify no violations found
        assertTrue(violations.isEmpty(), "Should not detect vulnerabilities in secure code");
    }
}