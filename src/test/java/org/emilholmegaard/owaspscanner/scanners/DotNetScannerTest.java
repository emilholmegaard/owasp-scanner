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

public class DotNetScannerTest {

    private DotNetScanner scanner;
    
    @TempDir
    Path tempDir;
    
    @BeforeEach
    public void setUp() {
        scanner = new DotNetScanner();
    }
    
    @Test
    public void testGetSupportedFileExtensions() {
        List<String> extensions = scanner.getSupportedFileExtensions();
        
        assertTrue(extensions.contains("cs"));
        assertTrue(extensions.contains("cshtml"));
        assertTrue(extensions.contains("config"));
        assertTrue(extensions.contains("json"));
    }
    
    @Test
    public void testCanProcessFile() {
        assertTrue(scanner.canProcessFile(Path.of("Controller.cs")));
        assertTrue(scanner.canProcessFile(Path.of("View.cshtml")));
        assertTrue(scanner.canProcessFile(Path.of("web.config")));
        assertTrue(scanner.canProcessFile(Path.of("appsettings.json")));
        
        assertFalse(scanner.canProcessFile(Path.of("script.js")));
        assertFalse(scanner.canProcessFile(Path.of("styles.css")));
        assertFalse(scanner.canProcessFile(Path.of("README.md")));
    }
    
    @Test
    public void testScanFileWithSqlInjectionVulnerability() throws IOException {
        // Create a temporary file with a SQL injection vulnerability
        Path testFile = tempDir.resolve("TestRepo.cs");
        String vulnerableCode = 
            "using System.Data.SqlClient;\n" +
            "public class UserRepository {\n" +
            "    private readonly string connectionString;\n" +
            "    \n" +
            "    public User GetUser(string username) {\n" +
            "        using (var conn = new SqlConnection(connectionString)) {\n" +
            "            conn.Open();\n" +
            "            // Vulnerable SQL query - concatenation\n" +
            "            var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\", conn);\n" +
            "            var reader = cmd.ExecuteReader();\n" +
            "            // Process results\n" +
            "            return new User();\n" +
            "        }\n" +
            "    }\n" +
            "}";
        
        Files.writeString(testFile, vulnerableCode);
        
        // Scan the file
        List<SecurityViolation> violations = scanner.scanFile(testFile);
        
        // Verify that the SQL injection vulnerability was detected
        assertFalse(violations.isEmpty(), "Should detect at least one violation");
        
        boolean foundSqlInjection = violations.stream()
            .anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-003"));
            
        assertTrue(foundSqlInjection, "Should detect SQL injection vulnerability");
    }
    
    @Test
    public void testScanFileWithSecureCode() throws IOException {
        // Create a temporary file with secure code
        Path testFile = tempDir.resolve("SecureRepo.cs");
        String secureCode = 
            "using System.Data.SqlClient;\n" +
            "public class UserRepository {\n" +
            "    private readonly string connectionString;\n" +
            "    \n" +
            "    public User GetUser(string username) {\n" +
            "        using (var conn = new SqlConnection(connectionString)) {\n" +
            "            conn.Open();\n" +
            "            // Secure parameterized query\n" +
            "            var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = @Username\", conn);\n" +
            "            cmd.Parameters.AddWithValue(\"@Username\", username);\n" +
            "            var reader = cmd.ExecuteReader();\n" +
            "            // Process results\n" +
            "            return new User();\n" +
            "        }\n" +
            "    }\n" +
            "}";
        
        Files.writeString(testFile, secureCode);
        
        // Scan the file
        List<SecurityViolation> violations = scanner.scanFile(testFile);
        
        // Verify that no SQL injection vulnerability was detected
        boolean foundSqlInjection = violations.stream()
            .anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-003"));
            
        assertFalse(foundSqlInjection, "Should not detect SQL injection in secure code");
    }
    
    @Test
    public void testScanFileWithMultipleVulnerabilities() throws IOException {
        // Create a temporary file with multiple vulnerabilities
        Path testFile = tempDir.resolve("MultipleVulnerabilities.cs");
        String vulnerableCode = 
            "using System.Data.SqlClient;\n" +
            "using System.Web.Mvc;\n" +
            "public class UserController : Controller {\n" +
            "    private readonly string connectionString;\n" +
            "    \n" +
            "    [HttpPost]\n" +
            "    public ActionResult Login(string username, string password) {\n" +
            "        // Missing CSRF protection - no ValidateAntiForgeryToken\n" +
            "        \n" +
            "        // SQL Injection vulnerability\n" +
            "        using (var conn = new SqlConnection(connectionString)) {\n" +
            "            conn.Open();\n" +
            "            var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\", conn);\n" +
            "            var reader = cmd.ExecuteReader();\n" +
            "            // Process results\n" +
            "        }\n" +
            "        \n" +
            "        // XSS vulnerability\n" +
            "        ViewBag.Message = \"Welcome \" + username;\n" +
            "        return View();\n" +
            "    }\n" +
            "    \n" +
            "    public ActionResult RenderHtml(string content) {\n" +
            "        // XSS vulnerability\n" +
            "        return Content(content, \"text/html\");\n" +
            "    }\n" +
            "}";
        
        Files.writeString(testFile, vulnerableCode);
        
        // Scan the file
        List<SecurityViolation> violations = scanner.scanFile(testFile);
        
        // Verify that multiple vulnerabilities were detected
        assertTrue(violations.size() >= 2, "Should detect multiple violations");
        
        boolean foundSqlInjection = violations.stream()
            .anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-003"));
            
        boolean foundCsrfVulnerability = violations.stream()
            .anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-005"));
            
        assertTrue(foundSqlInjection, "Should detect SQL injection vulnerability");
        assertTrue(foundCsrfVulnerability, "Should detect CSRF vulnerability");
    }
}
