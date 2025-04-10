package org.emilholmegaard.owaspscanner.performance;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the performance testing framework.
 */
@SpringBootTest
@ActiveProfiles("test")
public class PerformanceTestFrameworkTest {

    @Autowired
    private PerformanceTest performanceTest;

    @TempDir
    Path tempDir;

    /**
     * Tests that the performance test framework can execute a scan on test data
     * and write results to a CSV file.
     */
    @Test
    public void testPerformanceFrameworkEndToEnd() throws IOException, InterruptedException {
        // Create test project structure
        Path testProjectDir = tempDir.resolve("TestProject");
        Files.createDirectories(testProjectDir);

        // Create some test files
        createTestFiles(testProjectDir);

        // Define output CSV file
        Path outputCsv = tempDir.resolve("test-results.csv");

        // Run the performance test (now using injected instance)
        performanceTest.runPerformanceTest(
                testProjectDir.toString(),
                outputCsv.toString(),
                "unit-test");

        // Verify results file was created
        assertTrue(Files.exists(outputCsv), "Results CSV file should be created");

        // Verify file has content (header + at least one data row)
        List<String> lines = Files.readAllLines(outputCsv);
        assertTrue(lines.size() >= 2, "CSV should have header and at least one data row");

        // Verify header structure
        String header = lines.get(0);
        assertTrue(header.contains("Timestamp"), "CSV header should contain Timestamp");
        assertTrue(header.contains("TestLabel"), "CSV header should contain TestLabel");
        assertTrue(header.contains("DurationMs"), "CSV header should contain DurationMs");
        assertTrue(header.contains("PeakMemoryMB"), "CSV header should contain PeakMemoryMB");

        // Verify data row contains our test label
        String dataRow = lines.get(1);
        assertTrue(dataRow.contains("unit-test"), "Data row should contain our test label");

        // Run the performance summary
        PerformanceSummary.generateSummary(outputCsv.toString(), null, null);

        // No assertions for summary, we just verify it doesn't throw exceptions
    }

    /**
     * Creates some test files with various vulnerabilities to scan.
     */
    private void createTestFiles(Path projectDir) throws IOException {
        // Create a vulnerable controller file
        Path controllerFile = projectDir.resolve("VulnerableController.cs");
        String controllerContent = "using System;\n" +
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
                "    }\n" +
                "}";

        Files.writeString(controllerFile, controllerContent);

        // Create a config file with secrets
        Path configFile = projectDir.resolve("appsettings.json");
        String configContent = "{\n" +
                "  \"ConnectionStrings\": {\n" +
                "    \"DefaultConnection\": \"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=PlainTextPassword123!\"\n"
                +
                "  },\n" +
                "  \"ApiSettings\": {\n" +
                "    \"ApiKey\": \"c8e5f279e4c94b1a96a0f6352431e9ee\",\n" +
                "    \"ApiSecret\": \"TotallySecretKeyThatShouldBeProtected\"\n" +
                "  }\n" +
                "}";

        Files.writeString(configFile, configContent);
    }
}
