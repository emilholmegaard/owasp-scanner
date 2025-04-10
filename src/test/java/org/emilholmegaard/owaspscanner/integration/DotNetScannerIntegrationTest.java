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
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = OwaspScannerApp.class)
@ActiveProfiles("test")
class DotNetScannerIntegrationTest {

    @Autowired
    private ScannerEngine scannerEngine;

    @Test
    void testScanProjectWithMultipleVulnerabilities(@TempDir Path tempDir) throws IOException {
        // Create test project directory
        Path testProjectDir = tempDir.resolve("TestDotNetProject");
        Files.createDirectories(testProjectDir);

        // Create test files
        createVulnerableControllerFile(testProjectDir);
        createVulnerableConfigFile(testProjectDir);
        createSecureRepositoryFile(testProjectDir);

        // Scan the directory
        List<SecurityViolation> violations = scannerEngine.scanDirectory(testProjectDir);

        // Print violations for debugging
        System.out.println("Found " + violations.size() + " violations:");
        violations.forEach(v -> System.out.println(" - " + v.getRuleId() + ": " + v.getDescription()));

        // Verify violations
        assertFalse(violations.isEmpty(), "Should detect at least one violation");

        assertTrue(
                violations.stream().anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-003")),
                "Should detect SQL Injection vulnerability");

        assertTrue(
                violations.stream().anyMatch(v -> v.getRuleId().equals("DOTNET-SEC-003") ||
                        v.getRuleId().equals("DOTNET-SEC-004") ||
                        v.getRuleId().equals("DOTNET-SEC-006")),
                "Should detect at least one kind of violation");

        // Verify secure file has no violations
        List<SecurityViolation> secureFileViolations = violations.stream()
                .filter(v -> v.getFilePath().getFileName().toString().equals("SecureRepository.cs"))
                .filter(v -> v.getRuleId().equals("DOTNET-SEC-003"))
                .collect(Collectors.toList());

        assertTrue(secureFileViolations.isEmpty(), "Secure file should not have SQL Injection violations");
    }

    private void createVulnerableControllerFile(Path projectDir) throws IOException {
        Path file = projectDir.resolve("VulnerableController.cs");

        String content = "using System.Data.SqlClient;\n" +
                "using System.Web.Mvc;\n" +
                "\n" +
                "namespace TestApp.Controllers {\n" +
                "    public class UserController : Controller {\n" +
                "        private readonly string connectionString;\n" +
                "        \n" +
                "        [HttpPost]\n" +
                "        public ActionResult Login(string username, string password) {\n" +
                "            // Missing CSRF protection\n" +
                "            \n" +
                "            // SQL Injection vulnerability\n" +
                "            using (var conn = new SqlConnection(connectionString)) {\n" +
                "                conn.Open();\n" +
                "                var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\", conn);\n"
                +
                "                var reader = cmd.ExecuteReader();\n" +
                "                // Process results\n" +
                "            }\n" +
                "            \n" +
                "            // XSS vulnerability\n" +
                "            ViewBag.Message = \"Welcome \" + username;\n" +
                "            return View();\n" +
                "        }\n" +
                "        \n" +
                "        public ActionResult RenderHtml(string content) {\n" +
                "            // XSS vulnerability using Response.Write\n" +
                "            Response.Write(content);\n" +
                "            return Content(content, \"text/html\");\n" +
                "        }\n" +
                "    }\n" +
                "}";

        Files.writeString(file, content);
    }

    private void createVulnerableConfigFile(Path projectDir) throws IOException {
        Path file = projectDir.resolve("appsettings.json");

        String content = "{\n" +
                "  \"ConnectionStrings\": {\n" +
                "    \"DefaultConnection\": \"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword123;\"\n"
                +
                "  },\n" +
                "  \"ApiKeys\": {\n" +
                "    \"ExternalService\": \"c8e5f279e4c94b1a96a0f6352431e9ee\"\n" +
                "  },\n" +
                "  \"SecretKey\": \"ThisIsASecretKeyInConfig\",\n" +
                "  \"Logging\": {\n" +
                "    \"LogLevel\": {\n" +
                "      \"Default\": \"Information\",\n" +
                "      \"Microsoft\": \"Warning\"\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Files.writeString(file, content);
    }

    private void createSecureRepositoryFile(Path projectDir) throws IOException {
        Path file = projectDir.resolve("SecureRepository.cs");

        String content = "using System.Data.SqlClient;\n" +
                "\n" +
                "namespace TestApp.Data {\n" +
                "    public class UserRepository {\n" +
                "        private readonly string connectionString;\n" +
                "        \n" +
                "        public User GetUser(string username) {\n" +
                "            // Secure parameterized query\n" +
                "            using (var conn = new SqlConnection(connectionString)) {\n" +
                "                conn.Open();\n" +
                "                var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = @Username\", conn);\n"
                +
                "                cmd.Parameters.AddWithValue(\"@Username\", username);\n" +
                "                var reader = cmd.ExecuteReader();\n" +
                "                // Process results\n" +
                "                return new User();\n" +
                "            }\n" +
                "        }\n" +
                "    }\n" +
                "}";

        Files.writeString(file, content);
    }
}