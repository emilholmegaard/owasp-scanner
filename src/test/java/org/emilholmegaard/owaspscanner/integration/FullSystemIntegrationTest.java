package org.emilholmegaard.owaspscanner.integration;

import org.emilholmegaard.owaspscanner.OwaspScannerApp;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.core.ScannerEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = OwaspScannerApp.class)
@ActiveProfiles("test")
class FullSystemIntegrationTest {

    @Autowired
    private ScannerEngine scannerEngine;

    @Test
    void testFullSystemIntegration(@TempDir Path tempDir) throws IOException {
        // Create test project structure
        Path projectDir = tempDir.resolve("FullTestProject");
        Files.createDirectories(projectDir);

        // Create test files with various vulnerabilities
        createVulnerableController(projectDir);
        createInsecureConfigFile(projectDir);
        createInsecureAuthenticationFile(projectDir);
        createSecureFile(projectDir);

        // Run the scan
        List<SecurityViolation> violations = scannerEngine.scanDirectory(projectDir);

        // Print out violations for debugging
        System.out.println("FullSystemIntegrationTest - Detected violations (" + violations.size() + " total):");
        violations.forEach(
                violation -> System.out.println(" - " + violation.getRuleId() + ": " + violation.getDescription() +
                        " in " + violation.getFilePath().getFileName()));

        // Verify we found multiple vulnerabilities
        assertTrue(violations.size() >= 3, "Should detect at least 3 different violations");

        // Group violations by rule ID
        Map<String, List<SecurityViolation>> violationsByRule = violations.stream()
                .collect(Collectors.groupingBy(SecurityViolation::getRuleId));

        // Check for SQL Injection (which should be the most reliable to detect)
        assertTrue(violationsByRule.containsKey("DOTNET-SEC-003"),
                "Should detect SQL Injection (DOTNET-SEC-003)");

        // Check that we detect at least 2 types of vulnerabilities
        assertTrue(violationsByRule.keySet().size() >= 2,
                "Should detect at least 2 different types of vulnerabilities");
    }

    private void createVulnerableController(Path projectDir) throws IOException {
        Path file = projectDir.resolve("VulnerableController.cs");

        String content = "using System;\n" +
                "using System.Data.SqlClient;\n" +
                "using System.Web.Mvc;\n" +
                "\n" +
                "namespace TestProject.Controllers {\n" +
                "    public class VulnerableController : Controller {\n" +
                "        private readonly string connectionString = \"Server=myserver;Database=mydb;User Id=myuser;Password=mypassword;\";\n"
                +
                "        \n" +
                "        [HttpPost]\n" +
                "        public ActionResult Search(string searchTerm) {\n" +
                "            // SQL Injection vulnerability\n" +
                "            using (var conn = new SqlConnection(connectionString)) {\n" +
                "                conn.Open();\n" +
                "                var cmd = new SqlCommand(\"SELECT * FROM Products WHERE Name LIKE '%\" + searchTerm + \"%'\", conn);\n"
                +
                "                var reader = cmd.ExecuteReader();\n" +
                "                // Process results\n" +
                "            }\n" +
                "            \n" +
                "            // XSS vulnerability\n" +
                "            ViewBag.SearchResults = \"Results for: \" + searchTerm;\n" +
                "            return View();\n" +
                "        }\n" +
                "        \n" +
                "        [HttpPost]\n" +
                "        public ActionResult ProcessForm(string username, string message) {\n" +
                "            // Missing CSRF protection\n" +
                "            // Missing input validation\n" +
                "            \n" +
                "            // XSS vulnerability with direct Response.Write\n" +
                "            Response.Write(\"<div>\" + username + \"</div>\");\n" +
                "            return Content(\"<h1>Message from \" + username + \"</h1><div>\" + message + \"</div>\", \"text/html\");\n"
                +
                "        }\n" +
                "        \n" +
                "        public ActionResult RenderHtml(string content) {\n" +
                "            // XSS vulnerability using @Html.Raw\n" +
                "            return Content(\"@Html.Raw(\" + content + \")\", \"text/html\");\n" +
                "        }\n" +
                "        \n" +
                "        public ActionResult HandleError() {\n" +
                "            try {\n" +
                "                // Some code that might throw\n" +
                "                throw new Exception(\"Something went wrong\");\n" +
                "            } catch (Exception ex) {\n" +
                "                // Insecure exception handling\n" +
                "                return Content(\"Error: \" + ex.Message + \"<br/>Stack trace: \" + ex.StackTrace, \"text/html\");\n"
                +
                "            }\n" +
                "        }\n" +
                "    }\n" +
                "}";

        Files.writeString(file, content);
    }

    private void createInsecureConfigFile(Path projectDir) throws IOException {
        Path file = projectDir.resolve("appsettings.json");

        String content = "{\n" +
                "  \"ConnectionStrings\": {\n" +
                "    \"DefaultConnection\": \"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=PlainTextPassword123!\"\n"
                +
                "  },\n" +
                "  \"ApiSettings\": {\n" +
                "    \"ApiKey\": \"c8e5f279e4c94b1a96a0f6352431e9ee\",\n" +
                "    \"ApiSecret\": \"TotallySecretKeyThatShouldBeProtected\"\n" +
                "  },\n" +
                "  \"Logging\": {\n" +
                "    \"LogLevel\": {\n" +
                "      \"Default\": \"Information\",\n" +
                "      \"Microsoft\": \"Warning\"\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Files.writeString(file, content);
    }

    private void createInsecureAuthenticationFile(Path projectDir) throws IOException {
        Path file = projectDir.resolve("UserService.cs");

        String content = "using System;\n" +
                "using System.Security.Cryptography;\n" +
                "using System.Text;\n" +
                "\n" +
                "namespace TestProject.Services {\n" +
                "    public class UserService {\n" +
                "        // Insecure password hashing\n" +
                "        public string HashPassword(string password) {\n" +
                "            using (SHA1 sha1 = SHA1.Create()) {\n" +
                "                byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));\n" +
                "                return Convert.ToBase64String(hashBytes);\n" +
                "            }\n" +
                "        }\n" +
                "        \n" +
                "        public bool VerifyPassword(string password, string hashedPassword) {\n" +
                "            string computedHash = HashPassword(password);\n" +
                "            return computedHash == hashedPassword;\n" +
                "        }\n" +
                "        \n" +
                "        public void CreateUser(string username, string password) {\n" +
                "            string hashedPassword = HashPassword(password);\n" +
                "            // Store user in database\n" +
                "        }\n" +
                "    }\n" +
                "}";

        Files.writeString(file, content);
    }

    private void createSecureFile(Path projectDir) throws IOException {
        Path file = projectDir.resolve("SecureController.cs");

        String content = "using System;\n" +
                "using System.Data.SqlClient;\n" +
                "using System.Web.Mvc;\n" +
                "using System.Text.Encodings.Web;\n" +
                "\n" +
                "namespace TestProject.Controllers {\n" +
                "    public class SecureController : Controller {\n" +
                "        private readonly string connectionString = \"...\"; // From config\n" +
                "        \n" +
                "        [HttpPost]\n" +
                "        [ValidateAntiForgeryToken]\n" +
                "        public ActionResult Search(string searchTerm) {\n" +
                "            // Secure SQL query\n" +
                "            using (var conn = new SqlConnection(connectionString)) {\n" +
                "                conn.Open();\n" +
                "                var cmd = new SqlCommand(\"SELECT * FROM Products WHERE Name LIKE @SearchTerm\", conn);\n"
                +
                "                cmd.Parameters.AddWithValue(\"@SearchTerm\", \"%" + "\" + searchTerm + \"" + "%\");\n"
                +
                "                var reader = cmd.ExecuteReader();\n" +
                "                // Process results\n" +
                "            }\n" +
                "            \n" +
                "            // XSS prevention\n" +
                "            ViewBag.SearchResults = \"Results for: \" + HtmlEncoder.Default.Encode(searchTerm);\n" +
                "            return View();\n" +
                "        }\n" +
                "    }\n" +
                "}";

        Files.writeString(file, content);
    }
}